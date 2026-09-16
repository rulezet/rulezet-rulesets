rule sig_20161207_4e0f90cbfa46d99c09bd786a30500fca {
  meta:
    description = "datamaliciousorder - file 20161207_4e0f90cbfa46d99c09bd786a30500fca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1be2a5fee8e34fe29296ffdf59849c32cc279e6df2054f771c94714d89683d1a"

  strings:
    $s1 = "var vVy2 = new Function(\"vCGq3\", '{return vCGq3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBYu7 = new Function(\"vCG" ascii
    $s2 = "8 = new Date();vPTx8[\"setUTCFullYear\"](\"2003\");if (vPTx8.getUTCFullYear().toString(10) == \"2003\") {var vHf6 = vCGq3.split(" ascii
    $s3 = "var vVy2 = new Function(\"vCGq3\", '{return vCGq3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBYu7 = new Function(\"vCG" ascii
    $s4 = "); return vHf6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}