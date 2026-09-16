rule sig_20161207_718b36a8db529f430a910e95e72182f8 {
  meta:
    description = "datamaliciousorder - file 20161207_718b36a8db529f430a910e95e72182f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f29191c981daf886af60f10dace3f5a205ea5714316fd562f322899e0364ea07"

  strings:
    $s1 = "new Date();vMPx2[\"setUTCFullYear\"](\"2003\");if (vMPx2.getUTCFullYear().toString(10) == \"2003\") {var vGAq2 = vVf8.split(\"##" ascii
    $s2 = "var vEz4 = new Function(\"vVf8\", '{return vVf8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIi6 = new Function(\"vVf8\"" ascii
    $s3 = "eturn vGAq2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEz4 = new Function(\"vVf8\", '{return vVf8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIi6 = new Function(\"vVf8\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}