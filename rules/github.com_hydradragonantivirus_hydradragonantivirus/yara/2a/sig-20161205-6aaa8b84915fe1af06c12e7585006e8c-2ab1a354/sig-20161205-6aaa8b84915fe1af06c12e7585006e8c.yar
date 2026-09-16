rule sig_20161205_6aaa8b84915fe1af06c12e7585006e8c {
  meta:
    description = "datamaliciousorder - file 20161205_6aaa8b84915fe1af06c12e7585006e8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7546b947544d8d557bb782081cbc4cf574c166295e9b0cee5539cf7bd322bf75"

  strings:
    $s1 = "function _YCh7(s) {var _Ct4 = new Date();_Ct4.setUTCFullYear(\"2003\");if (_Ct4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YCh7(s) {var _Ct4 = new Date();_Ct4.setUTCFullYear(\"2003\");if (_Ct4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Zb4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}