rule sig_20161205_56d20342fd09b513e824873d4d8bfbd1 {
  meta:
    description = "datamaliciousorder - file 20161205_56d20342fd09b513e824873d4d8bfbd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b0012dd3315313c52e27ae5024a45a23d558d102423ebb28de73248475e4211"

  strings:
    $s1 = "function _CKj4(s) {var _MMz9 = new Date();_MMz9.setUTCFullYear(\"2003\");if (_MMz9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CKj4(s) {var _MMz9 = new Date();_MMz9.setUTCFullYear(\"2003\");if (_MMz9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Hv0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}