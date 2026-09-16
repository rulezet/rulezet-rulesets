rule sig_20161205_49136a8a0c59ee49f6d21ac76b17075e {
  meta:
    description = "datamaliciousorder - file 20161205_49136a8a0c59ee49f6d21ac76b17075e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8f90c91be421fb90435394a8ce3b6876b472ebc609ea4f0331a37496e42a63e"

  strings:
    $s1 = "function _Dp6(s) {var _KIe0 = new Date();_KIe0.setUTCFullYear(\"2003\");if (_KIe0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Dp6(s) {var _KIe0 = new Date();_KIe0.setUTCFullYear(\"2003\");if (_KIe0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Jg0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}