rule sig_20161205_b3d483a0ce483dc9ba5daa3fc6e95df9 {
  meta:
    description = "datamaliciousorder - file 20161205_b3d483a0ce483dc9ba5daa3fc6e95df9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec06f6f71c08edd72da44809e7ab3b124604b0faf7a294738c6f75854f70edf9"

  strings:
    $s1 = "function _FQr4(s) {var _Ld0 = new Date();_Ld0.setUTCFullYear(\"2003\");if (_Ld0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _FQr4(s) {var _Ld0 = new Date();_Ld0.setUTCFullYear(\"2003\");if (_Ld0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ja0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}