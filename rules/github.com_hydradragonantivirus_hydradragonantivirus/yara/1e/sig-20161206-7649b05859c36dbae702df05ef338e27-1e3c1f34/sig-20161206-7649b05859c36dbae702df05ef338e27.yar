rule sig_20161206_7649b05859c36dbae702df05ef338e27 {
  meta:
    description = "datamaliciousorder - file 20161206_7649b05859c36dbae702df05ef338e27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41c7a4d739fb496f93585e20b9bc482a4ea4c3cfe6ae720b6ea874a36ccc045e"

  strings:
    $s1 = "function _Pc6(s) {var _Fh6 = new Date();_Fh6.setUTCFullYear(\"2003\");if (_Fh6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Pc6(s) {var _Fh6 = new Date();_Fh6.setUTCFullYear(\"2003\");if (_Fh6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _UTk0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}