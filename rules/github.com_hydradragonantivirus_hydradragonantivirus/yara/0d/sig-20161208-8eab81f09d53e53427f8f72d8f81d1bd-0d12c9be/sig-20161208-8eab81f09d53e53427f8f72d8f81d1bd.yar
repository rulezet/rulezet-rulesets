rule sig_20161208_8eab81f09d53e53427f8f72d8f81d1bd {
  meta:
    description = "datamaliciousorder - file 20161208_8eab81f09d53e53427f8f72d8f81d1bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a535e7deb2bf28904ccca717bd2d93c6124ffcc834991a6f45ea34e8d1772f8"

  strings:
    $s1 = " = new Date();vJg5[\"setUTC\"+\"FullYear\"](\"2003\");if (vJg5.getUTCFullYear().toString(10) == \"2003\") {var vLp3 = vBWh6.spli" ascii
    $s2 = "var vMTu8 = new Function(\"vBWh6\", '{return vBWh6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKm6 = new Function(\"vBW" ascii
    $s3 = "var vMTu8 = new Function(\"vBWh6\", '{return vBWh6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKm6 = new Function(\"vBW" ascii
    $s4 = "); return vLp3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}