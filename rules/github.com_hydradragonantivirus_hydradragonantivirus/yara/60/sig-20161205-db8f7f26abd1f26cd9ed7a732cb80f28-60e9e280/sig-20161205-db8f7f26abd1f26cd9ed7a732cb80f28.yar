rule sig_20161205_db8f7f26abd1f26cd9ed7a732cb80f28 {
  meta:
    description = "datamaliciousorder - file 20161205_db8f7f26abd1f26cd9ed7a732cb80f28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87254f71fe2ec6dee152696aaa3e6350657c6b171ddf2a18a0f0a9c38773485d"

  strings:
    $s1 = "function _YNo9(s) {var _Cl6 = new Date();_Cl6.setUTCFullYear(\"2003\");if (_Cl6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YNo9(s) {var _Cl6 = new Date();_Cl6.setUTCFullYear(\"2003\");if (_Cl6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _GEv6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}