rule sig_20161205_70c7a8b9c3fa241af6252f6123501b5d {
  meta:
    description = "datamaliciousorder - file 20161205_70c7a8b9c3fa241af6252f6123501b5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4281baea3886785bc96f5934741407e181bdca1a2309f7d532434611cf63599f"

  strings:
    $s1 = "function _MNs9(s) {var _NHz6 = new Date();_NHz6.setUTCFullYear(\"2003\");if (_NHz6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MNs9(s) {var _NHz6 = new Date();_NHz6.setUTCFullYear(\"2003\");if (_NHz6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Kp0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}