rule sig_20161206_aba480b968a044894181366d839a445a {
  meta:
    description = "datamaliciousorder - file 20161206_aba480b968a044894181366d839a445a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "029e6d247c340f75d44139a75ec93f8cdf094ac2f1dd7fa2c13d9eeba97c5d6d"

  strings:
    $s1 = "var vRRy7 = new Function(\"s\", '{var vKXg9 = new Date();vKXg9[\"setUTCFullYear\"](\"2003\");if (vKXg9.getUTCFullYear().toString" ascii
    $s2 = "var vRRy7 = new Function(\"s\", '{var vKXg9 = new Date();vKXg9[\"setUTCFullYear\"](\"2003\");if (vKXg9.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vJp5 = s.split(\"##\"); return vJp5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vYCq7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}