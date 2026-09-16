rule sig_20160826_55c2d64d7051737fbaf111dd134776a8 {
  meta:
    description = "datamaliciousorder - file 20160826_55c2d64d7051737fbaf111dd134776a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aba8951ce0cf18269c35eb2772c59fc7d49993cefe44c3c3d7ef2e49b5775bee"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}