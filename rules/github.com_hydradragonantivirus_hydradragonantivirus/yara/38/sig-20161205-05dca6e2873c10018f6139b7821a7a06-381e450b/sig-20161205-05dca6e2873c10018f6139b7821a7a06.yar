rule sig_20161205_05dca6e2873c10018f6139b7821a7a06 {
  meta:
    description = "datamaliciousorder - file 20161205_05dca6e2873c10018f6139b7821a7a06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b88548002d8ecd16af8951b35d0c87d91dddaf7c463afeab3722167281a57004"

  strings:
    $s1 = "function _TQw0(s) {var _CJv3 = new Date();_CJv3.setUTCFullYear(\"2003\");if (_CJv3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _TQw0(s) {var _CJv3 = new Date();_CJv3.setUTCFullYear(\"2003\");if (_CJv3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Qd9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}