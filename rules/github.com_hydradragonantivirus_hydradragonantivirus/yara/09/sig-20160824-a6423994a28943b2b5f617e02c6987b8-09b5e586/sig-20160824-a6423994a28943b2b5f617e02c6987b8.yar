rule sig_20160824_a6423994a28943b2b5f617e02c6987b8 {
  meta:
    description = "datamaliciousorder - file 20160824_a6423994a28943b2b5f617e02c6987b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8017bbf1c6555523c383532d82e0e5f745e45061c398c063bd9776c1dd3659af"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}