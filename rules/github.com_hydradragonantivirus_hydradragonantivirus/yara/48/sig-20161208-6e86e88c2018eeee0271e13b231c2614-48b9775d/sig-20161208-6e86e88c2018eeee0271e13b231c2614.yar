rule sig_20161208_6e86e88c2018eeee0271e13b231c2614 {
  meta:
    description = "datamaliciousorder - file 20161208_6e86e88c2018eeee0271e13b231c2614.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebefaba6f6ae8facace2ab9bf05c7e4c8de42ad6912f69234fbccfbc8ac987c5"

  strings:
    $s1 = "var vAVj6 = new Function(\"vIVg3\", '{return vIVg3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIKg4 = new Function(\"vI" ascii
    $s2 = "h2 = new Date();vMYh2[\"setUTC\"+\"FullYear\"](\"2003\");if (vMYh2.getUTCFullYear().toString(10) == \"2003\") {var vVh8 = vIVg3." ascii
    $s3 = "var vAVj6 = new Function(\"vIVg3\", '{return vIVg3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIKg4 = new Function(\"vI" ascii
    $s4 = "###\"); return vVh8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}