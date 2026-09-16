rule sig_20161205_0da1ea80f3f90c1f3395b7c2466c0089 {
  meta:
    description = "datamaliciousorder - file 20161205_0da1ea80f3f90c1f3395b7c2466c0089.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35680f118d0b99de73c619e5914d04428f4d441e70ad9efe1f527e9b701f9be9"

  strings:
    $s1 = "function _FQm8(s) {var _AQj0 = new Date();_AQj0.setUTCFullYear(\"2003\");if (_AQj0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _FQm8(s) {var _AQj0 = new Date();_AQj0.setUTCFullYear(\"2003\");if (_AQj0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Wv5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}