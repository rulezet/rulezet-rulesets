rule sig_20161208_699930ff4ae0a9576a5437398f9e9df2 {
  meta:
    description = "datamaliciousorder - file 20161208_699930ff4ae0a9576a5437398f9e9df2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e880fa6907baf22e8a9e38b7415c97d6368181774182cbf51c1cbd1d655507c"

  strings:
    $s1 = "5 = new Date();vJHc5[\"setUTC\"+\"FullYear\"](\"2003\");if (vJHc5.getUTCFullYear().toString(10) == \"2003\") {var vVQj6 = vDXu8." ascii
    $s2 = "var vUx1 = new Function(\"vDXu8\", '{return vDXu8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEJl2 = new Function(\"vDX" ascii
    $s3 = "var vUx1 = new Function(\"vDXu8\", '{return vDXu8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEJl2 = new Function(\"vDX" ascii
    $s4 = "###\"); return vVQj6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}