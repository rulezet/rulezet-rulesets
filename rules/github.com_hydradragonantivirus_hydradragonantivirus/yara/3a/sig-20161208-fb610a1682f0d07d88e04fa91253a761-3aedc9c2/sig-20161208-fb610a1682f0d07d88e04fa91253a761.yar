rule sig_20161208_fb610a1682f0d07d88e04fa91253a761 {
  meta:
    description = "datamaliciousorder - file 20161208_fb610a1682f0d07d88e04fa91253a761.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bd5ac237a33015b82db2c98aea2111c95341919e474d9e6c36033f88c8a967"

  strings:
    $s1 = "var vEd0 = new Function(\"vSz0\", '{return vSz0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMQn7 = new Function(\"vSz0" ascii
    $s2 = " new Date();vFLz6[\"setUTC\"+\"FullYear\"](\"2003\");if (vFLz6.getUTCFullYear().toString(10) == \"2003\") {var vWt7 = vSz0.split" ascii
    $s3 = "; return vWt7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEd0 = new Function(\"vSz0\", '{return vSz0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMQn7 = new Function(\"vSz0" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}