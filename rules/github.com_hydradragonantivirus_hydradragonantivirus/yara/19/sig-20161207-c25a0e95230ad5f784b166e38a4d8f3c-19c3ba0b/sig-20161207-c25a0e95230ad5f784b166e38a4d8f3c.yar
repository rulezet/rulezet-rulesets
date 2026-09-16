rule sig_20161207_c25a0e95230ad5f784b166e38a4d8f3c {
  meta:
    description = "datamaliciousorder - file 20161207_c25a0e95230ad5f784b166e38a4d8f3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5eddfcb7c7547698c22817123421687e63c904e64deae5a2e3dc3715ebe48411"

  strings:
    $s1 = "new Date();vFq1[\"setUTCFullYear\"](\"2003\");if (vFq1.getUTCFullYear().toString(10) == \"2003\") {var vXy9 = vCs7.split(\"####" ascii
    $s2 = "var vIXr9 = new Function(\"vCs7\", '{return vCs7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBx4 = new Function(\"vCs7" ascii
    $s3 = "var vIXr9 = new Function(\"vCs7\", '{return vCs7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBx4 = new Function(\"vCs7" ascii
    $s4 = "rn vXy9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}