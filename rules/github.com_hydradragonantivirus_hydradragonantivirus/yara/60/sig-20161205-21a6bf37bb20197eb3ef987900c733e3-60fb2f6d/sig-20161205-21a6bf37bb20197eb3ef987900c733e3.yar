rule sig_20161205_21a6bf37bb20197eb3ef987900c733e3 {
  meta:
    description = "datamaliciousorder - file 20161205_21a6bf37bb20197eb3ef987900c733e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "975b55e9c0de58a2c1d76f0efed4e6659694a25feb9c68fcb931ebaada4549ab"

  strings:
    $s1 = "function _Bu6(s) {var _IDb0 = new Date();_IDb0.setUTCFullYear(\"2003\");if (_IDb0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Bu6(s) {var _IDb0 = new Date();_IDb0.setUTCFullYear(\"2003\");if (_IDb0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _KAv1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}