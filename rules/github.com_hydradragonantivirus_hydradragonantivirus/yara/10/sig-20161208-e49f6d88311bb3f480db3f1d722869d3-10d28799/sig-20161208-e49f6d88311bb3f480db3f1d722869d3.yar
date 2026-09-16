rule sig_20161208_e49f6d88311bb3f480db3f1d722869d3 {
  meta:
    description = "datamaliciousorder - file 20161208_e49f6d88311bb3f480db3f1d722869d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b4aeacf1905288259a8b5f136d4a9a65944efbf20c1e10b8680db719154fd64"

  strings:
    $s1 = "var vSq0 = new Function(\"vUl3\", '{return vUl3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFj7 = new Function(\"vUl3\"" ascii
    $s2 = "ew Date();vAf6[\"setUTC\"+\"FullYear\"](\"2003\");if (vAf6.getUTCFullYear().toString(10) == \"2003\") {var vMOc6 = vUl3.split(\"" ascii
    $s3 = "var vSq0 = new Function(\"vUl3\", '{return vUl3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFj7 = new Function(\"vUl3\"" ascii
    $s4 = "eturn vMOc6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}