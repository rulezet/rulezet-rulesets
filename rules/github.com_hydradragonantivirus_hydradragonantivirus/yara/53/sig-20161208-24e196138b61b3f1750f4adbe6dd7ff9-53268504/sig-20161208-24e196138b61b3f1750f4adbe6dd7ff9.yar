rule sig_20161208_24e196138b61b3f1750f4adbe6dd7ff9 {
  meta:
    description = "datamaliciousorder - file 20161208_24e196138b61b3f1750f4adbe6dd7ff9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "754f95a7363e3c38ecbf1185640aa09b61441253e64ecf9b2a90c94f0311cf73"

  strings:
    $s1 = "var vUQg6 = new Function(\"vSAv4\", '{return vSAv4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUOn8 = new Function(\"vS" ascii
    $s2 = "f8 = new Date();vTTf8[\"setUTC\"+\"FullYear\"](\"2003\");if (vTTf8.getUTCFullYear().toString(10) == \"2003\") {var vZy5 = vSAv4." ascii
    $s3 = "var vUQg6 = new Function(\"vSAv4\", '{return vSAv4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUOn8 = new Function(\"vS" ascii
    $s4 = "###\"); return vZy5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}