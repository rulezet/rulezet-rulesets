rule sig_20161205_fbb35a860dba447e896b838eff1fd518 {
  meta:
    description = "datamaliciousorder - file 20161205_fbb35a860dba447e896b838eff1fd518.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06113adeb35e32543fef251c58c277c353227fec9b2766c344f28fdaf722f589"

  strings:
    $s1 = "function _BQd4(s) {var _Cu5 = new Date();_Cu5.setUTCFullYear(\"2003\");if (_Cu5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BQd4(s) {var _Cu5 = new Date();_Cu5.setUTCFullYear(\"2003\");if (_Cu5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Aa4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}