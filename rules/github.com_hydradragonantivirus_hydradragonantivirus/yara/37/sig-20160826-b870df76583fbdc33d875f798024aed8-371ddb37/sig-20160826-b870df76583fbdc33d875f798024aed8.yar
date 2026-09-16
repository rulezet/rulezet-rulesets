rule sig_20160826_b870df76583fbdc33d875f798024aed8 {
  meta:
    description = "datamaliciousorder - file 20160826_b870df76583fbdc33d875f798024aed8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23f9585861344d806b36ff571b4c424a5132235ba0fdb6ccdd014f87ec42c34b"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}