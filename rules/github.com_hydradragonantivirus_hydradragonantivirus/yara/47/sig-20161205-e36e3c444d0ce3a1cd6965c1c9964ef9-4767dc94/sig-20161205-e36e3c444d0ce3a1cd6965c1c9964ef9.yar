rule sig_20161205_e36e3c444d0ce3a1cd6965c1c9964ef9 {
  meta:
    description = "datamaliciousorder - file 20161205_e36e3c444d0ce3a1cd6965c1c9964ef9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1da952f637fd16ee930cb6f67abb04e2592bdd014f8fbe372c6ee035a8238bd"

  strings:
    $s1 = "function _Xr6(s) {var _AFk0 = new Date();_AFk0.setUTCFullYear(\"2003\");if (_AFk0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xr6(s) {var _AFk0 = new Date();_AFk0.setUTCFullYear(\"2003\");if (_AFk0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Hn2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}