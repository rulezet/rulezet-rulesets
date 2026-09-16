rule sig_20161205_b036ab78434714ba1e5ff98b1c5e227a {
  meta:
    description = "datamaliciousorder - file 20161205_b036ab78434714ba1e5ff98b1c5e227a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5c6223be7f56e7e0d41e2140ecab36b4c378fb1d623965b70ecf80e1d96d637"

  strings:
    $s1 = "function _Ep5(s) {var _CXk1 = new Date();_CXk1.setUTCFullYear(\"2003\");if (_CXk1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ep5(s) {var _CXk1 = new Date();_CXk1.setUTCFullYear(\"2003\");if (_CXk1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _RBz2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}