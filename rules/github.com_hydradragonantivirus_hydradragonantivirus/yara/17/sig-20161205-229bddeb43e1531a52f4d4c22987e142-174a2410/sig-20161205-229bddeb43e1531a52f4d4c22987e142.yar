rule sig_20161205_229bddeb43e1531a52f4d4c22987e142 {
  meta:
    description = "datamaliciousorder - file 20161205_229bddeb43e1531a52f4d4c22987e142.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e37cb0bd0e9330c05b370a62bd4072b8267ac2c74189ee49c5aeeaeb359737f2"

  strings:
    $s1 = "function _GXk5(s) {var _Qp6 = new Date();_Qp6.setUTCFullYear(\"2003\");if (_Qp6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _GXk5(s) {var _Qp6 = new Date();_Qp6.setUTCFullYear(\"2003\");if (_Qp6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Is4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}