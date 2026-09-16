rule sig_20161208_ea43b4c76d35e9a8910c1dfc02e8eb71 {
  meta:
    description = "datamaliciousorder - file 20161208_ea43b4c76d35e9a8910c1dfc02e8eb71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "888a1afb2a5b24f36ed5dc8966bec5b849aa2449db106ddc775d7426679d02ae"

  strings:
    $s1 = "6 = new Date();vZf6[\"setUTC\"+\"FullYear\"](\"2003\");if (vZf6.getUTCFullYear().toString(10) == \"2003\") {var vKWf8 = vWJo4.sp" ascii
    $s2 = "var vPKj2 = new Function(\"vWJo4\", '{return vWJo4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKYc5 = new Function(\"vW" ascii
    $s3 = "#\"); return vKWf8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vPKj2 = new Function(\"vWJo4\", '{return vWJo4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKYc5 = new Function(\"vW" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}