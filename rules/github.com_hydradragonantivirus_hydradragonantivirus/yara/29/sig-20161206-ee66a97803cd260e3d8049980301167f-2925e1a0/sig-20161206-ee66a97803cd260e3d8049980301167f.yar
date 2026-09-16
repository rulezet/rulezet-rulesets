rule sig_20161206_ee66a97803cd260e3d8049980301167f {
  meta:
    description = "datamaliciousorder - file 20161206_ee66a97803cd260e3d8049980301167f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d1276d16d1701b7cc774f0920b814140c09d9f5864c42dfe0248ff3dc16186d"

  strings:
    $s1 = "function _NEo4(s) {var _WYu2 = new Date();_WYu2.setUTCFullYear(\"2003\");if (_WYu2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _NEo4(s) {var _WYu2 = new Date();_WYu2.setUTCFullYear(\"2003\");if (_WYu2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Xd4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}