rule sig_20161205_95fd6593b26994f6e01c3f1927360807 {
  meta:
    description = "datamaliciousorder - file 20161205_95fd6593b26994f6e01c3f1927360807.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17c816a49cfcd835079a35e1c9aab0df362a46c82f39c213bc323f8ebd048475"

  strings:
    $s1 = "function _Ih7(s) {var _HCv3 = new Date();_HCv3.setUTCFullYear(\"2003\");if (_HCv3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ih7(s) {var _HCv3 = new Date();_HCv3.setUTCFullYear(\"2003\");if (_HCv3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _LRl0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}