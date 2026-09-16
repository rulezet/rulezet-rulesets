rule sig_20161205_d5a01debe2c6a6a3b280cd2beec5d2f9 {
  meta:
    description = "datamaliciousorder - file 20161205_d5a01debe2c6a6a3b280cd2beec5d2f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e2518a17300991e349e0f2a3578c80a08cba73f5e978d8e2d0a54923d2ace81"

  strings:
    $s1 = "function _LFv1(s) {var _SLw1 = new Date();_SLw1.setUTCFullYear(\"2003\");if (_SLw1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LFv1(s) {var _SLw1 = new Date();_SLw1.setUTCFullYear(\"2003\");if (_SLw1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Rf2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}