rule sig_20161208_dd3a11bfb596d61b9e95c6452199b5b0 {
  meta:
    description = "datamaliciousorder - file 20161208_dd3a11bfb596d61b9e95c6452199b5b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01ee730b732ddf5fe9d04a22b24c7cf9a5d4dc38b796dcf11c2acca692bfd5bb"

  strings:
    $s1 = "new Date();vUf1[\"setUTC\"+\"FullYear\"](\"2003\");if (vUf1.getUTCFullYear().toString(10) == \"2003\") {var vAr5 = vIl6.split(\"" ascii
    $s2 = "var vOe0 = new Function(\"vIl6\", '{return vIl6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGIy6 = new Function(\"vIl6" ascii
    $s3 = "eturn vAr5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vOe0 = new Function(\"vIl6\", '{return vIl6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGIy6 = new Function(\"vIl6" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}