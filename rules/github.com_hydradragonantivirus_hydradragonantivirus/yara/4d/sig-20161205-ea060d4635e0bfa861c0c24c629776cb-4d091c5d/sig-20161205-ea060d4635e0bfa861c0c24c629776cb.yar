rule sig_20161205_ea060d4635e0bfa861c0c24c629776cb {
  meta:
    description = "datamaliciousorder - file 20161205_ea060d4635e0bfa861c0c24c629776cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f0596d85014319ee4925e43eda594a7c590fdd9ab18020acc2c5e85f4ea26a4"

  strings:
    $s1 = "function _Ar0(s) {var _NKr1 = new Date();_NKr1.setUTCFullYear(\"2003\");if (_NKr1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ar0(s) {var _NKr1 = new Date();_NKr1.setUTCFullYear(\"2003\");if (_NKr1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Fg4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}