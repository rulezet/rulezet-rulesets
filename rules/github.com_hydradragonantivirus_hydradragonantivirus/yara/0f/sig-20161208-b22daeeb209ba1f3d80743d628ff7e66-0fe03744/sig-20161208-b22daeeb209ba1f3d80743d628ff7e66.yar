rule sig_20161208_b22daeeb209ba1f3d80743d628ff7e66 {
  meta:
    description = "datamaliciousorder - file 20161208_b22daeeb209ba1f3d80743d628ff7e66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d85347f2512c65fa60fc11ac98122189e7d070edb51fa319597ba8e512daa6e"

  strings:
    $s1 = "var vAm6 = new Function(\"vQDd7\", '{return vQDd7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSNi3 = new Function(\"vQD" ascii
    $s2 = " = new Date();vUt2[\"setUTC\"+\"FullYear\"](\"2003\");if (vUt2.getUTCFullYear().toString(10) == \"2003\") {var vYe9 = vQDd7.spli" ascii
    $s3 = "); return vYe9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vAm6 = new Function(\"vQDd7\", '{return vQDd7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSNi3 = new Function(\"vQD" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}