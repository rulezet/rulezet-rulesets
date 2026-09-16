rule sig_20160824_13c630e813da113334c43383ed64ecb5 {
  meta:
    description = "datamaliciousorder - file 20160824_13c630e813da113334c43383ed64ecb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "424786c4c346e018b5642e0a6f6343ebb138c781982082582bde41e47ea433d2"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}