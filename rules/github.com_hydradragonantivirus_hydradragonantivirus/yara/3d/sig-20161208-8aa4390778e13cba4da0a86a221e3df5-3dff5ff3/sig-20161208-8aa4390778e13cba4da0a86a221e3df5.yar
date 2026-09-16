rule sig_20161208_8aa4390778e13cba4da0a86a221e3df5 {
  meta:
    description = "datamaliciousorder - file 20161208_8aa4390778e13cba4da0a86a221e3df5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee1be49886b64e305179184a1e27ef1c233e6076d8718c0ec6d00d2b813e690"

  strings:
    $s1 = "var vLg8 = new Function(\"vCl7\", '{return vCl7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOa2 = new Function(\"vCl7\"" ascii
    $s2 = "new Date();vQMl7[\"setUTC\"+\"FullYear\"](\"2003\");if (vQMl7.getUTCFullYear().toString(10) == \"2003\") {var vCf2 = vCl7.split(" ascii
    $s3 = "var vLg8 = new Function(\"vCl7\", '{return vCl7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOa2 = new Function(\"vCl7\"" ascii
    $s4 = " return vCf2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}