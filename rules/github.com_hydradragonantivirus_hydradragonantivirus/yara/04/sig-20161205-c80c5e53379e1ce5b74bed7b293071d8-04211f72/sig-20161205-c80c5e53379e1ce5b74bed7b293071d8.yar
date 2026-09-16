rule sig_20161205_c80c5e53379e1ce5b74bed7b293071d8 {
  meta:
    description = "datamaliciousorder - file 20161205_c80c5e53379e1ce5b74bed7b293071d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af78c4febcb82c57a1f1c869f7a95341f548dd47cef71749cbbb962beb89b0c1"

  strings:
    $s1 = "function _Cc7(s) {var _QMv0 = new Date();_QMv0.setUTCFullYear(\"2003\");if (_QMv0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Cc7(s) {var _QMv0 = new Date();_QMv0.setUTCFullYear(\"2003\");if (_QMv0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _VAx2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}