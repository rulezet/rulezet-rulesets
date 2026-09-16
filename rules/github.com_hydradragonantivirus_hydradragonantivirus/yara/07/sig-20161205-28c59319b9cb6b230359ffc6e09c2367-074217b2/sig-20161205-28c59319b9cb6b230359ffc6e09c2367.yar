rule sig_20161205_28c59319b9cb6b230359ffc6e09c2367 {
  meta:
    description = "datamaliciousorder - file 20161205_28c59319b9cb6b230359ffc6e09c2367.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03904ef5c6e453b3051853764bc66da05508067011c4d029ebeed0112080087e"

  strings:
    $s1 = "function _Ss2(s) {var _IIs1 = new Date();_IIs1.setUTCFullYear(\"2003\");if (_IIs1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ss2(s) {var _IIs1 = new Date();_IIs1.setUTCFullYear(\"2003\");if (_IIs1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _YIr9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}