rule sig_20161208_dd6829e426636fe45e810bc0ac1942f0 {
  meta:
    description = "datamaliciousorder - file 20161208_dd6829e426636fe45e810bc0ac1942f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33baacb34ed7134fb16b18716045bc16e253351bf9dbc3b062dbad8aa7094a5e"

  strings:
    $s1 = "new Date();vJVa8[\"setUTC\"+\"FullYear\"](\"2003\");if (vJVa8.getUTCFullYear().toString(10) == \"2003\") {var vZQy0 = vJx2.split" ascii
    $s2 = "var vSb1 = new Function(\"vJx2\", '{return vJx2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFh8 = new Function(\"vJx2\"" ascii
    $s3 = "; return vZQy0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSb1 = new Function(\"vJx2\", '{return vJx2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFh8 = new Function(\"vJx2\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}