rule sig_20161205_e490dfad41bc865424789389e0c6f179 {
  meta:
    description = "datamaliciousorder - file 20161205_e490dfad41bc865424789389e0c6f179.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b761263f0bb4669d323745b088ecdd61d59a75c7b0b5ff0363381b9886797f8e"

  strings:
    $s1 = "function _TYo1(s) {var _Xn4 = new Date();_Xn4.setUTCFullYear(\"2003\");if (_Xn4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _TYo1(s) {var _Xn4 = new Date();_Xn4.setUTCFullYear(\"2003\");if (_Xn4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _RMv6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}