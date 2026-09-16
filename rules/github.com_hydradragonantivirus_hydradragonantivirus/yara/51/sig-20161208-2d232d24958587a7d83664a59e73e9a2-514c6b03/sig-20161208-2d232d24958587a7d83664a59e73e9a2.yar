rule sig_20161208_2d232d24958587a7d83664a59e73e9a2 {
  meta:
    description = "datamaliciousorder - file 20161208_2d232d24958587a7d83664a59e73e9a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a5b199adc26e1980e4b612e4a400048f9b3a848e7aeb6898dd0a3d56cd68254"

  strings:
    $s1 = " new Date();vOYh9[\"setUTC\"+\"FullYear\"](\"2003\");if (vOYh9.getUTCFullYear().toString(10) == \"2003\") {var vNr4 = vMy0.split" ascii
    $s2 = "var vDUj0 = new Function(\"vMy0\", '{return vMy0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTt8 = new Function(\"vMy0" ascii
    $s3 = "; return vNr4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vDUj0 = new Function(\"vMy0\", '{return vMy0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTt8 = new Function(\"vMy0" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}