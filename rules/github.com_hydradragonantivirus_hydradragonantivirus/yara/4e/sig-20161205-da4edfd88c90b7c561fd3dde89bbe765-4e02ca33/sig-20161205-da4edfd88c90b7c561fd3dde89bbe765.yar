rule sig_20161205_da4edfd88c90b7c561fd3dde89bbe765 {
  meta:
    description = "datamaliciousorder - file 20161205_da4edfd88c90b7c561fd3dde89bbe765.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b5d9b662bcc470c3e8ac51ba59b64f3efd8a99572f76350580b543a822c5de"

  strings:
    $s1 = "function _AOt8(s) {var _BCc5 = new Date();_BCc5.setUTCFullYear(\"2003\");if (_BCc5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _AOt8(s) {var _BCc5 = new Date();_BCc5.setUTCFullYear(\"2003\");if (_BCc5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _TCs4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}