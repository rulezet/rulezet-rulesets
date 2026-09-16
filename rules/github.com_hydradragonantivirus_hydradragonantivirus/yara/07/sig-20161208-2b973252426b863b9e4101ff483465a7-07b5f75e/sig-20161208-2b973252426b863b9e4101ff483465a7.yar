rule sig_20161208_2b973252426b863b9e4101ff483465a7 {
  meta:
    description = "datamaliciousorder - file 20161208_2b973252426b863b9e4101ff483465a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f843081e3af9984198410c6c6fa21527cd6c16d4e3d762939200dff9c9bce942"

  strings:
    $s1 = "var vRAs5 = new Function(\"vJJk0\", '{return vJJk0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYCy6 = new Function(\"vJ" ascii
    $s2 = "5 = new Date();vId5[\"setUTC\"+\"FullYear\"](\"2003\");if (vId5.getUTCFullYear().toString(10) == \"2003\") {var vHa4 = vJJk0.spl" ascii
    $s3 = "var vRAs5 = new Function(\"vJJk0\", '{return vJJk0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYCy6 = new Function(\"vJ" ascii
    $s4 = "\"); return vHa4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}