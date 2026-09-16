rule sig_20161208_e30568e55cf8494cb347d88e26aabced {
  meta:
    description = "datamaliciousorder - file 20161208_e30568e55cf8494cb347d88e26aabced.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d2ddccee8a0d523e72dd2ab0a07641f675a1d3ff57b4c6b42831b1fe4cc57af"

  strings:
    $s1 = "0 = new Date();vLYp0[\"setUTC\"+\"FullYear\"](\"2003\");if (vLYp0.getUTCFullYear().toString(10) == \"2003\") {var vQXj5 = vLYs8." ascii
    $s2 = "var vEXp5 = new Function(\"vLYs8\", '{return vLYs8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTd9 = new Function(\"vLY" ascii
    $s3 = "var vEXp5 = new Function(\"vLYs8\", '{return vLYs8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTd9 = new Function(\"vLY" ascii
    $s4 = "###\"); return vQXj5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}