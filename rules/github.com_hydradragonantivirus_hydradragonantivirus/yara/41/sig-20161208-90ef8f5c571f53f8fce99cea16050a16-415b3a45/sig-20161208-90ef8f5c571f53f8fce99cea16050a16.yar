rule sig_20161208_90ef8f5c571f53f8fce99cea16050a16 {
  meta:
    description = "datamaliciousorder - file 20161208_90ef8f5c571f53f8fce99cea16050a16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78a47dd47449848ce99a8ff133dd9638b58ea8ea14ea010bb7dcaf01dceec10f"

  strings:
    $s1 = " = new Date();vPYc2[\"setUTC\"+\"FullYear\"](\"2003\");if (vPYc2.getUTCFullYear().toString(10) == \"2003\") {var vHb0 = vZSp5.sp" ascii
    $s2 = "var vJb8 = new Function(\"vZSp5\", '{return vZSp5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSc1 = new Function(\"vZSp" ascii
    $s3 = "#\"); return vHb0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vJb8 = new Function(\"vZSp5\", '{return vZSp5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSc1 = new Function(\"vZSp" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}