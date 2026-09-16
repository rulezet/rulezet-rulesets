rule sig_20161205_b8451aa2f064b0005e0a63e33d300e50 {
  meta:
    description = "datamaliciousorder - file 20161205_b8451aa2f064b0005e0a63e33d300e50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e571dfb94515bdc19dd3e11db0acefb79732114975725811fceca73095bc95de"

  strings:
    $s1 = "function _Zd6(s) {var _Na8 = new Date();_Na8.setUTCFullYear(\"2003\");if (_Na8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Zd6(s) {var _Na8 = new Date();_Na8.setUTCFullYear(\"2003\");if (_Na8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _XIv3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}