rule sig_20161205_3f1d7664595d2ff885b9fa3bf8a96bbf {
  meta:
    description = "datamaliciousorder - file 20161205_3f1d7664595d2ff885b9fa3bf8a96bbf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4370948896e4b1d2fded7d0a85127f5c2e1564e41ecbc47c810ae76b1473ac4"

  strings:
    $s1 = "function _YJr6(s) {var _RJd4 = new Date();_RJd4.setUTCFullYear(\"2003\");if (_RJd4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YJr6(s) {var _RJd4 = new Date();_RJd4.setUTCFullYear(\"2003\");if (_RJd4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ZBy2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}