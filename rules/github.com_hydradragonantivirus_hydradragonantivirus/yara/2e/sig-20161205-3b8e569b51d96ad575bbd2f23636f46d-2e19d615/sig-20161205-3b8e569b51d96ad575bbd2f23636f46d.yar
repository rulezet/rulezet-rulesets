rule sig_20161205_3b8e569b51d96ad575bbd2f23636f46d {
  meta:
    description = "datamaliciousorder - file 20161205_3b8e569b51d96ad575bbd2f23636f46d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d4e48b6b029a6ef2fdc1edf65941be4386f9a908bc863688dfd040adcc10a13"

  strings:
    $s1 = "function _LSl8(s) {var _NKf0 = new Date();_NKf0.setUTCFullYear(\"2003\");if (_NKf0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LSl8(s) {var _NKf0 = new Date();_NKf0.setUTCFullYear(\"2003\");if (_NKf0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Bj5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}