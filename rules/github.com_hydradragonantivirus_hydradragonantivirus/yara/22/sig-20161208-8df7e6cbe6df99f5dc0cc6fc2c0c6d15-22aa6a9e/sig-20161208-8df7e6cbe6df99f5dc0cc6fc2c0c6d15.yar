rule sig_20161208_8df7e6cbe6df99f5dc0cc6fc2c0c6d15 {
  meta:
    description = "datamaliciousorder - file 20161208_8df7e6cbe6df99f5dc0cc6fc2c0c6d15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b653b7db749d061a1829070e729a3f1e1eeaea2ff3a99ba8529e24e9a75b33f8"

  strings:
    $s1 = " new Date();vJe5[\"setUTC\"+\"FullYear\"](\"2003\");if (vJe5.getUTCFullYear().toString(10) == \"2003\") {var vGy1 = vDk6.split(" ascii
    $s2 = "var vHOo9 = new Function(\"vDk6\", '{return vDk6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQPc3 = new Function(\"vDk6" ascii
    $s3 = "var vHOo9 = new Function(\"vDk6\", '{return vDk6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQPc3 = new Function(\"vDk6" ascii
    $s4 = "return vGy1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}