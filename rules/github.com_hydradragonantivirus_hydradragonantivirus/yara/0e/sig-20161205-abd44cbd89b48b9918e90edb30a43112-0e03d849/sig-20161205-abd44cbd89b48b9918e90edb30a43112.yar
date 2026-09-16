rule sig_20161205_abd44cbd89b48b9918e90edb30a43112 {
  meta:
    description = "datamaliciousorder - file 20161205_abd44cbd89b48b9918e90edb30a43112.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7bee93f89fbb1ffe6228b684f03b41f791ac73ba9b075e34b36ada5382dbcc2"

  strings:
    $s1 = "function _Qs6(s) {var _Ra80 = new Date();_Ra80.setUTCFullYear(\"2003\");if (_Ra80.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qs6(s) {var _Ra80 = new Date();_Ra80.setUTCFullYear(\"2003\");if (_Ra80.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _LXh1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}