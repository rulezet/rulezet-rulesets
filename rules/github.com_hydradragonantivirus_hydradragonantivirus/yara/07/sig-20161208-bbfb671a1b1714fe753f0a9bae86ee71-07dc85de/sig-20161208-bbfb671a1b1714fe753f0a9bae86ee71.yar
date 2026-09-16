rule sig_20161208_bbfb671a1b1714fe753f0a9bae86ee71 {
  meta:
    description = "datamaliciousorder - file 20161208_bbfb671a1b1714fe753f0a9bae86ee71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d4f270ff01978fdf0cc9d743fbb27582a753e26dedc4f8151f1d3bd40f294d0"

  strings:
    $s1 = " = new Date();vLZa5[\"setUTC\"+\"FullYear\"](\"2003\");if (vLZa5.getUTCFullYear().toString(10) == \"2003\") {var vEBq1 = vYLt4.s" ascii
    $s2 = "var vGk9 = new Function(\"vYLt4\", '{return vYLt4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJe5 = new Function(\"vYLt" ascii
    $s3 = "##\"); return vEBq1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGk9 = new Function(\"vYLt4\", '{return vYLt4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJe5 = new Function(\"vYLt" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}