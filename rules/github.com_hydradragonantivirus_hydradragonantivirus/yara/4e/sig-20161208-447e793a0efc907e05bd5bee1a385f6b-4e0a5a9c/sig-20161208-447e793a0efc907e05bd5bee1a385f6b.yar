rule sig_20161208_447e793a0efc907e05bd5bee1a385f6b {
  meta:
    description = "datamaliciousorder - file 20161208_447e793a0efc907e05bd5bee1a385f6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66924ecd70e0eca3eaec92b19105c4eac57200cfd0b4d3dc5aec7a05437561a8"

  strings:
    $s1 = "var vXSw5 = new Function(\"vWm4\", '{return vWm4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGUc6 = new Function(\"vWm4" ascii
    $s2 = "= new Date();vVBr1[\"setUTC\"+\"FullYear\"](\"2003\");if (vVBr1.getUTCFullYear().toString(10) == \"2003\") {var vKXe3 = vWm4.spl" ascii
    $s3 = "var vXSw5 = new Function(\"vWm4\", '{return vWm4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGUc6 = new Function(\"vWm4" ascii
    $s4 = "\"); return vKXe3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}