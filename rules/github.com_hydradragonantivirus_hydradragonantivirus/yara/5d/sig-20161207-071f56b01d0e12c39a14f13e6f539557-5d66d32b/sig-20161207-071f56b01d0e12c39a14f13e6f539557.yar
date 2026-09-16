rule sig_20161207_071f56b01d0e12c39a14f13e6f539557 {
  meta:
    description = "datamaliciousorder - file 20161207_071f56b01d0e12c39a14f13e6f539557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9186c8530ff618073b3cb7ecd3270784dba7cd324f6b725ccdc36810f1307d1"

  strings:
    $s1 = "new Date();vNv9[\"setUTCFullYear\"](\"2003\");if (vNv9.getUTCFullYear().toString(10) == \"2003\") {var vYq5 = vVm8.split(\"####" ascii
    $s2 = "var vPz3 = new Function(\"vVm8\", '{return vVm8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRRe6 = new Function(\"vVm8" ascii
    $s3 = "rn vYq5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vPz3 = new Function(\"vVm8\", '{return vVm8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRRe6 = new Function(\"vVm8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}