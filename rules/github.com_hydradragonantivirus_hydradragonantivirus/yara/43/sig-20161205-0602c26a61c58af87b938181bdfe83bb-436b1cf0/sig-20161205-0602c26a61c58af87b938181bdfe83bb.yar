rule sig_20161205_0602c26a61c58af87b938181bdfe83bb {
  meta:
    description = "datamaliciousorder - file 20161205_0602c26a61c58af87b938181bdfe83bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8db43869250099a63fc63f639dc4d43ff4c9905571b2ef2a0a1c34267185870d"

  strings:
    $s1 = "function _HLi4(s) {var _FMy8 = new Date();_FMy8.setUTCFullYear(\"2003\");if (_FMy8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HLi4(s) {var _FMy8 = new Date();_FMy8.setUTCFullYear(\"2003\");if (_FMy8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _SAn6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}