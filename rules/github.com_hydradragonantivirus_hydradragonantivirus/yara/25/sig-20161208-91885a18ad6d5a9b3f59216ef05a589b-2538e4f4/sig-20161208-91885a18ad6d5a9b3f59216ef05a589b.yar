rule sig_20161208_91885a18ad6d5a9b3f59216ef05a589b {
  meta:
    description = "datamaliciousorder - file 20161208_91885a18ad6d5a9b3f59216ef05a589b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ac5ba4a18bc0b8dd1d711eb0ba8a830662312df1d773ee4d9c4ea06ccfe7e46"

  strings:
    $s1 = "2 = new Date();vSAm2[\"setUTC\"+\"FullYear\"](\"2003\");if (vSAm2.getUTCFullYear().toString(10) == \"2003\") {var vSm9 = vJXt5.s" ascii
    $s2 = "var vTQl4 = new Function(\"vJXt5\", '{return vJXt5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKr8 = new Function(\"vJX" ascii
    $s3 = "##\"); return vSm9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTQl4 = new Function(\"vJXt5\", '{return vJXt5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKr8 = new Function(\"vJX" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}