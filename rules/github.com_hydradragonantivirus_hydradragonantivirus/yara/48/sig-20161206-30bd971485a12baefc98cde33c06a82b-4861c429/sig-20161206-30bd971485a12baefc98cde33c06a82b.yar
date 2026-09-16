rule sig_20161206_30bd971485a12baefc98cde33c06a82b {
  meta:
    description = "datamaliciousorder - file 20161206_30bd971485a12baefc98cde33c06a82b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8f026a28d7c8fdb3eb03efbf4852d8dfc600d394561d85132f5736a90a3c0ad"

  strings:
    $s1 = "function _HBd8(s) {var _Hf6 = new Date();_Hf6.setUTCFullYear(\"2003\");if (_Hf6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _HBd8(s) {var _Hf6 = new Date();_Hf6.setUTCFullYear(\"2003\");if (_Hf6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Tq1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}