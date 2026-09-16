rule sig_20161208_19b63a3d7930959a13b5e20eb3a2a0ef {
  meta:
    description = "datamaliciousorder - file 20161208_19b63a3d7930959a13b5e20eb3a2a0ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd5f080d9703ed53150fb2a974bb54fe6e438a53ef9213120ca13fc95e81236e"

  strings:
    $s1 = " new Date();vKQr4[\"setUTC\"+\"FullYear\"](\"2003\");if (vKQr4.getUTCFullYear().toString(10) == \"2003\") {var vLSd2 = vVm3.spli" ascii
    $s2 = "var vQNh7 = new Function(\"vVm3\", '{return vVm3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGk3 = new Function(\"vVm3" ascii
    $s3 = "); return vLSd2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vQNh7 = new Function(\"vVm3\", '{return vVm3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGk3 = new Function(\"vVm3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}