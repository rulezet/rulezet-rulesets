rule sig_20161208_e51811a0337bedbe6f1b315ced92539d {
  meta:
    description = "datamaliciousorder - file 20161208_e51811a0337bedbe6f1b315ced92539d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c60bd0ac308c2a0f3d933586f59548269af1c66241eb1f3be449e60264463a9e"

  strings:
    $s1 = "new Date();vKs5[\"setUTC\"+\"FullYear\"](\"2003\");if (vKs5.getUTCFullYear().toString(10) == \"2003\") {var vFSg6 = vKq7.split(" ascii
    $s2 = "var vRz6 = new Function(\"vKq7\", '{return vKq7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXWk4 = new Function(\"vKq7" ascii
    $s3 = "return vFSg6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vRz6 = new Function(\"vKq7\", '{return vKq7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXWk4 = new Function(\"vKq7" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}