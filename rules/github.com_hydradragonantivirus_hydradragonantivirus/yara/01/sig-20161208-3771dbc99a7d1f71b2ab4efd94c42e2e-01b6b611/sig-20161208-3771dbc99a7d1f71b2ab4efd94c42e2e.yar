rule sig_20161208_3771dbc99a7d1f71b2ab4efd94c42e2e {
  meta:
    description = "datamaliciousorder - file 20161208_3771dbc99a7d1f71b2ab4efd94c42e2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89de106117e07b2f31d8691020cd7ea9daafdb01f842546f4305ae0c86899ae8"

  strings:
    $s1 = "var vDUm8 = new Function(\"vMs0\", '{return vMs0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTs9 = new Function(\"vMs0" ascii
    $s2 = " new Date();vEOk8[\"setUTC\"+\"FullYear\"](\"2003\");if (vEOk8.getUTCFullYear().toString(10) == \"2003\") {var vXBf6 = vMs0.spli" ascii
    $s3 = "var vDUm8 = new Function(\"vMs0\", '{return vMs0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTs9 = new Function(\"vMs0" ascii
    $s4 = "); return vXBf6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}