rule sig_20161205_100008bbc736af07046b2402686345ab {
  meta:
    description = "datamaliciousorder - file 20161205_100008bbc736af07046b2402686345ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a1d1c5e75724f1ddc46071f3bb38d6ddd9713adfd0b5bf05df4598f410a1331"

  strings:
    $s1 = "function _XJi3(s) {var _Ps9 = new Date();_Ps9.setUTCFullYear(\"2003\");if (_Ps9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _XJi3(s) {var _Ps9 = new Date();_Ps9.setUTCFullYear(\"2003\");if (_Ps9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _TAz5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}