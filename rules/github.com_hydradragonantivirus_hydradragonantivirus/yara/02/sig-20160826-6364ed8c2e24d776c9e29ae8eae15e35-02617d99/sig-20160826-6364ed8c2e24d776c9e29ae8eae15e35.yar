rule sig_20160826_6364ed8c2e24d776c9e29ae8eae15e35 {
  meta:
    description = "datamaliciousorder - file 20160826_6364ed8c2e24d776c9e29ae8eae15e35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dd112702273ca5855d181a78829fea5edf32811c8ee7560c99836f404150d31"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}