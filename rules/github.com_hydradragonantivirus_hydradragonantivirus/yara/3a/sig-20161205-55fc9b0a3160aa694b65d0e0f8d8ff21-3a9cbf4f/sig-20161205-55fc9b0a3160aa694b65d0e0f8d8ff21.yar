rule sig_20161205_55fc9b0a3160aa694b65d0e0f8d8ff21 {
  meta:
    description = "datamaliciousorder - file 20161205_55fc9b0a3160aa694b65d0e0f8d8ff21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc03f0f82fcab7e5167c762ce68a29eebdbc5c4e150f0c2f09707671dcfaaf9b"

  strings:
    $s1 = "function _GNf6(s) {var _Fi1 = new Date();_Fi1.setUTCFullYear(\"2003\");if (_Fi1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _GNf6(s) {var _Fi1 = new Date();_Fi1.setUTCFullYear(\"2003\");if (_Fi1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Xy8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}