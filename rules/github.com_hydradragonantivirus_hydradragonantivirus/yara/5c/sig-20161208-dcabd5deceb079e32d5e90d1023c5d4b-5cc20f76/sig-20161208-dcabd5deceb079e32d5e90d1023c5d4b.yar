rule sig_20161208_dcabd5deceb079e32d5e90d1023c5d4b {
  meta:
    description = "datamaliciousorder - file 20161208_dcabd5deceb079e32d5e90d1023c5d4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81fd7b2a1832386410e225f53681c22d6aff5af71d39b96370a9345ee36d16fa"

  strings:
    $s1 = "new Date();vIg9[\"setUTC\"+\"FullYear\"](\"2003\");if (vIg9.getUTCFullYear().toString(10) == \"2003\") {var vGl2 = vWs3.split(\"" ascii
    $s2 = "var vJDy6 = new Function(\"vWs3\", '{return vWs3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIw8 = new Function(\"vWs3" ascii
    $s3 = "var vJDy6 = new Function(\"vWs3\", '{return vWs3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIw8 = new Function(\"vWs3" ascii
    $s4 = "eturn vGl2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}