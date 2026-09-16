rule sig_20161208_2aed1ee1d7817bd149e1df4b14733bbf {
  meta:
    description = "datamaliciousorder - file 20161208_2aed1ee1d7817bd149e1df4b14733bbf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c203df2eac58354b97a11f1bd03ea0c20013e62df486c7b826aab5d82bfce451"

  strings:
    $s1 = "var vTTd3 = new Function(\"vZKg6\", '{return vZKg6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOZt5 = new Function(\"vZ" ascii
    $s2 = "1 = new Date();vCc1[\"setUTC\"+\"FullYear\"](\"2003\");if (vCc1.getUTCFullYear().toString(10) == \"2003\") {var vEQv8 = vZKg6.sp" ascii
    $s3 = "var vTTd3 = new Function(\"vZKg6\", '{return vZKg6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOZt5 = new Function(\"vZ" ascii
    $s4 = "#\"); return vEQv8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}