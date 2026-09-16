rule sig_20161205_610e531b69b5cba8215ee2a025e98fd5 {
  meta:
    description = "datamaliciousorder - file 20161205_610e531b69b5cba8215ee2a025e98fd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12ab02799dade137f7244e972c3ed49f55e3cbf8ce95a4fe0989db7af5d833b1"

  strings:
    $s1 = "function _RUa1(s) {var _Pk5 = new Date();_Pk5.setUTCFullYear(\"2003\");if (_Pk5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _RUa1(s) {var _Pk5 = new Date();_Pk5.setUTCFullYear(\"2003\");if (_Pk5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Su9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}