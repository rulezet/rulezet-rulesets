rule sig_20161207_12c8f9188235ec588be1608ab91c2fa7 {
  meta:
    description = "datamaliciousorder - file 20161207_12c8f9188235ec588be1608ab91c2fa7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ca27612c495b9ce68051e13c15ca130ea0c1bc6257596a808d247ad283926f5"

  strings:
    $s1 = "var vEKk6 = new Function(\"vRXm1\", '{return vRXm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRJa5 = new Function(\"vR" ascii
    $s2 = "p0 = new Date();vRWp0[\"setUTCFullYear\"](\"2003\");if (vRWp0.getUTCFullYear().toString(10) == \"2003\") {var vGPz4 = vRXm1.spli" ascii
    $s3 = "#\"); return vGPz4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEKk6 = new Function(\"vRXm1\", '{return vRXm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRJa5 = new Function(\"vR" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}