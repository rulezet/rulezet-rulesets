rule sig_20161207_46709358b976701978ce084d0cfa0b12 {
  meta:
    description = "datamaliciousorder - file 20161207_46709358b976701978ce084d0cfa0b12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a30a04acb59ad37db70dc262e0f2143990b72c4c00cb8e51bb4f75d7121706f6"

  strings:
    $s1 = "var vIv7 = new Function(\"vBd9\", '{var vCAx7 = new Date();vCAx7[\"setUTCFullYear\"](\"2003\");if (vCAx7.getUTCFullYear().toStri" ascii
    $s2 = "var vIv7 = new Function(\"vBd9\", '{var vCAx7 = new Date();vCAx7[\"setUTCFullYear\"](\"2003\");if (vCAx7.getUTCFullYear().toStri" ascii
    $s3 = "var vCFy5 = new Function(\"vBd9\", '{return vBd9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vNSu2 = vBd9.split(\"###\"); return vNSu2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}