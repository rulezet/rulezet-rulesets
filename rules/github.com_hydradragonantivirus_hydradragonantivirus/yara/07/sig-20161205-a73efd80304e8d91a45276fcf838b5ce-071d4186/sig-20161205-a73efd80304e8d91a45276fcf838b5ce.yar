rule sig_20161205_a73efd80304e8d91a45276fcf838b5ce {
  meta:
    description = "datamaliciousorder - file 20161205_a73efd80304e8d91a45276fcf838b5ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3c63b28d71491679c27437280b44061b3338f137b46f0fb10a455b241e2d9d"

  strings:
    $s1 = "function _ERp2(s) {var _DQf4 = new Date();_DQf4.setUTCFullYear(\"2003\");if (_DQf4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ERp2(s) {var _DQf4 = new Date();_DQf4.setUTCFullYear(\"2003\");if (_DQf4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Av2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}