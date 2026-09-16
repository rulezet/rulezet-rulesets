rule sig_20161205_278863f49fbf0778f9ebbc3228e7c922 {
  meta:
    description = "datamaliciousorder - file 20161205_278863f49fbf0778f9ebbc3228e7c922.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f309d152a8bf78fd025a85b2511a54b66158b9f63fdb3b379e4daeb888be45a"

  strings:
    $s1 = "function _Wi2(s) {var _Cj5 = new Date();_Cj5.setUTCFullYear(\"2003\");if (_Cj5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Wi2(s) {var _Cj5 = new Date();_Cj5.setUTCFullYear(\"2003\");if (_Cj5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Cv6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}