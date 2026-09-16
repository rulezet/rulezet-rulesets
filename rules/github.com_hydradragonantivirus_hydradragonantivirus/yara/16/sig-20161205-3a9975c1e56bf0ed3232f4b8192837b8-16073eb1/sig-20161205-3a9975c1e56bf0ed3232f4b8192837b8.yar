rule sig_20161205_3a9975c1e56bf0ed3232f4b8192837b8 {
  meta:
    description = "datamaliciousorder - file 20161205_3a9975c1e56bf0ed3232f4b8192837b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c11930d38d5f929fe9db6bd8f0da411fefc7e9efe46a831ceff1f31c752048bf"

  strings:
    $s1 = "function _Tu6(s) {var _XYu2 = new Date();_XYu2.setUTCFullYear(\"2003\");if (_XYu2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Tu6(s) {var _XYu2 = new Date();_XYu2.setUTCFullYear(\"2003\");if (_XYu2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Nj1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}