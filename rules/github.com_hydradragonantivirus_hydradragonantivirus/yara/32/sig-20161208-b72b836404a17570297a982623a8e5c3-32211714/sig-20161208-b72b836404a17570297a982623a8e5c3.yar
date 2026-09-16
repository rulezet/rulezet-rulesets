rule sig_20161208_b72b836404a17570297a982623a8e5c3 {
  meta:
    description = "datamaliciousorder - file 20161208_b72b836404a17570297a982623a8e5c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "873179779a18d833432b7f5c97c33381fac7c3f6d0946d8e385ccdd6b023f85c"

  strings:
    $s1 = "9 = new Date();vWn9[\"setUTC\"+\"FullYear\"](\"2003\");if (vWn9.getUTCFullYear().toString(10) == \"2003\") {var vCq8 = vVOa7.spl" ascii
    $s2 = "var vWKr1 = new Function(\"vVOa7\", '{return vVOa7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUSc7 = new Function(\"vV" ascii
    $s3 = "\"); return vCq8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWKr1 = new Function(\"vVOa7\", '{return vVOa7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUSc7 = new Function(\"vV" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}