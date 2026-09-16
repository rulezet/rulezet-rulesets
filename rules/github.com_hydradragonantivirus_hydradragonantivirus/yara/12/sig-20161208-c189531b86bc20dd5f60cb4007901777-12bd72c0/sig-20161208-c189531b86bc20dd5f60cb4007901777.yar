rule sig_20161208_c189531b86bc20dd5f60cb4007901777 {
  meta:
    description = "datamaliciousorder - file 20161208_c189531b86bc20dd5f60cb4007901777.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c22adad3109a9f0ec19f17b8f6464c7a71115e12af94d46ef74e3bbc7101a78a"

  strings:
    $s1 = " = new Date();vGi8[\"setUTC\"+\"FullYear\"](\"2003\");if (vGi8.getUTCFullYear().toString(10) == \"2003\") {var vPj8 = vAHh6.spli" ascii
    $s2 = "var vXu7 = new Function(\"vAHh6\", '{return vAHh6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIFe6 = new Function(\"vAH" ascii
    $s3 = "); return vPj8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vXu7 = new Function(\"vAHh6\", '{return vAHh6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIFe6 = new Function(\"vAH" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}