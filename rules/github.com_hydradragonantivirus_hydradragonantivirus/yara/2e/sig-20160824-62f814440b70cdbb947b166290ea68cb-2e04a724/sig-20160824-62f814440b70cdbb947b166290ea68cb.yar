rule sig_20160824_62f814440b70cdbb947b166290ea68cb {
  meta:
    description = "datamaliciousorder - file 20160824_62f814440b70cdbb947b166290ea68cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a00b0715b128f50fcea8f041d4d66d0086cd64f73fe57f33de2c12826e7a0bb1"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}