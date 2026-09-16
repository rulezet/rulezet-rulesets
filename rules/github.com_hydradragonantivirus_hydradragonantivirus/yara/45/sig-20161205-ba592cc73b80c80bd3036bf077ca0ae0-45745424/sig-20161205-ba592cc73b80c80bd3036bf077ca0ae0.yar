rule sig_20161205_ba592cc73b80c80bd3036bf077ca0ae0 {
  meta:
    description = "datamaliciousorder - file 20161205_ba592cc73b80c80bd3036bf077ca0ae0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59c1770a0e26f87be955d2457f73e140c2f6825b73eba977b381894bf3ee78d8"

  strings:
    $s1 = "function _Ge6(s) {var _BCk7 = new Date();_BCk7.setUTCFullYear(\"2003\");if (_BCk7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ge6(s) {var _BCk7 = new Date();_BCk7.setUTCFullYear(\"2003\");if (_BCk7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _LGs5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}