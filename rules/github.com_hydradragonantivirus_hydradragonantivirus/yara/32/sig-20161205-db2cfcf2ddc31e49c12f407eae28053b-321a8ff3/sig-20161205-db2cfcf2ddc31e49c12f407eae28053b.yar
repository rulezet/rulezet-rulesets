rule sig_20161205_db2cfcf2ddc31e49c12f407eae28053b {
  meta:
    description = "datamaliciousorder - file 20161205_db2cfcf2ddc31e49c12f407eae28053b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6606bf494f8d587c472ab2b27ada319a9717c32106cde74a9c422a71516c7191"

  strings:
    $s1 = "function _HKl9(s) {var _ZPt6 = new Date();_ZPt6.setUTCFullYear(\"2003\");if (_ZPt6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HKl9(s) {var _ZPt6 = new Date();_ZPt6.setUTCFullYear(\"2003\");if (_ZPt6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _QIb8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}