rule sig_20160826_bc74a88c5dc270574f98d70a5592f5bf {
  meta:
    description = "datamaliciousorder - file 20160826_bc74a88c5dc270574f98d70a5592f5bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edb54a9608f7bdb63bed7bc690b3436a8250fd79ea2145dbde31f6264fa7caa0"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}