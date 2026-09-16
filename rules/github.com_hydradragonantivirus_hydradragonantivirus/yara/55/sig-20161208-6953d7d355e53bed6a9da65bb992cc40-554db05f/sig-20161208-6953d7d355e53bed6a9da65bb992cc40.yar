rule sig_20161208_6953d7d355e53bed6a9da65bb992cc40 {
  meta:
    description = "datamaliciousorder - file 20161208_6953d7d355e53bed6a9da65bb992cc40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7be02202db167d9610ac6263af7ed9bd803b455b2c44fd5611ab7341652e776"

  strings:
    $s1 = "var vSk0 = new Function(\"vPm9\", '{return vPm9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQb7 = new Function(\"vPm9\"" ascii
    $s2 = "ew Date();vKa5[\"setUTC\"+\"FullYear\"](\"2003\");if (vKa5.getUTCFullYear().toString(10) == \"2003\") {var vMDi4 = vPm9.split(\"" ascii
    $s3 = "eturn vMDi4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSk0 = new Function(\"vPm9\", '{return vPm9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQb7 = new Function(\"vPm9\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}