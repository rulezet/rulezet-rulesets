rule sig_20161205_0b1f97993b53143d09abfb0b01552c6a {
  meta:
    description = "datamaliciousorder - file 20161205_0b1f97993b53143d09abfb0b01552c6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f30e95ecb130772238cff3db1e4a880c01b4290d0561f99666d085ed97884e2"

  strings:
    $s1 = "function _Wg7(s) {var _ZIi3 = new Date();_ZIi3.setUTCFullYear(\"2003\");if (_ZIi3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Wg7(s) {var _ZIi3 = new Date();_ZIi3.setUTCFullYear(\"2003\");if (_ZIi3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _XOz7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}