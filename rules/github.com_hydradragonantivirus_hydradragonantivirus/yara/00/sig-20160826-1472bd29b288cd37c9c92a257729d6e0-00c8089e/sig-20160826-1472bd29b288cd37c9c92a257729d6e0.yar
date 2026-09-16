rule sig_20160826_1472bd29b288cd37c9c92a257729d6e0 {
  meta:
    description = "datamaliciousorder - file 20160826_1472bd29b288cd37c9c92a257729d6e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e6ab86cbb613d51ad7f22b072d6042e8340688c9a062bfa569d2a628b9ee"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}