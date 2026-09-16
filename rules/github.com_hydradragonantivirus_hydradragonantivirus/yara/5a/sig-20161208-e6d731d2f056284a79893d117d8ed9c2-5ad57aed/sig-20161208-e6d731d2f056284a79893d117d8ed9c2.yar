rule sig_20161208_e6d731d2f056284a79893d117d8ed9c2 {
  meta:
    description = "datamaliciousorder - file 20161208_e6d731d2f056284a79893d117d8ed9c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1891eda9a4d380db6a2046f6c5790e26435a02d796a83175dc1d6cde572a2484"

  strings:
    $s1 = "4 = new Date();vUTd4[\"setUTC\"+\"FullYear\"](\"2003\");if (vUTd4.getUTCFullYear().toString(10) == \"2003\") {var vLHa8 = vUNx2." ascii
    $s2 = "var vTTn0 = new Function(\"vUNx2\", '{return vUNx2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEa7 = new Function(\"vUN" ascii
    $s3 = "var vTTn0 = new Function(\"vUNx2\", '{return vUNx2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEa7 = new Function(\"vUN" ascii
    $s4 = "###\"); return vLHa8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}