rule sig_20160826_1473470d9925b97e1d1c2ac85960d5f1 {
  meta:
    description = "datamaliciousorder - file 20160826_1473470d9925b97e1d1c2ac85960d5f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20d213bbd91d0a6b93b2c302dc43c58e95d79b27c000e02d4727b027f2aba43a"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}