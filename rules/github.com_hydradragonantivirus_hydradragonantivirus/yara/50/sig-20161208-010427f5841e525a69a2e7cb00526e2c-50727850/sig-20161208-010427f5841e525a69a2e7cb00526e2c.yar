rule sig_20161208_010427f5841e525a69a2e7cb00526e2c {
  meta:
    description = "datamaliciousorder - file 20161208_010427f5841e525a69a2e7cb00526e2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8665ee1229cfb335f9c891eea88c5ea401cfd5b91ae4a8616e85cf57c306457"

  strings:
    $s1 = " new Date();vIc3[\"setUTC\"+\"FullYear\"](\"2003\");if (vIc3.getUTCFullYear().toString(10) == \"2003\") {var vJVj7 = vBg4.split(" ascii
    $s2 = "var vRBr3 = new Function(\"vBg4\", '{return vBg4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFNv0 = new Function(\"vBg4" ascii
    $s3 = " return vJVj7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vRBr3 = new Function(\"vBg4\", '{return vBg4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFNv0 = new Function(\"vBg4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}