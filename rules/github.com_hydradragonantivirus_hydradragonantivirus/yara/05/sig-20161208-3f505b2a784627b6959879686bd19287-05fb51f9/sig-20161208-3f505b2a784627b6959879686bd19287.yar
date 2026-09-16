rule sig_20161208_3f505b2a784627b6959879686bd19287 {
  meta:
    description = "datamaliciousorder - file 20161208_3f505b2a784627b6959879686bd19287.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40ed7b7e88292559598b20cf7baf55d382dcaadbded3c11aceb5b8682d52d65d"

  strings:
    $s1 = " new Date();vWUo1[\"setUTC\"+\"FullYear\"](\"2003\");if (vWUo1.getUTCFullYear().toString(10) == \"2003\") {var vPh1 = vFa2.split" ascii
    $s2 = "var vSAf4 = new Function(\"vFa2\", '{return vFa2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQa4 = new Function(\"vFa2" ascii
    $s3 = "; return vPh1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSAf4 = new Function(\"vFa2\", '{return vFa2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQa4 = new Function(\"vFa2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}