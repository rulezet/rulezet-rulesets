rule sig_20160824_1a47eedbf63dd232a748ee393c4a5ee5 {
  meta:
    description = "datamaliciousorder - file 20160824_1a47eedbf63dd232a748ee393c4a5ee5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2f878a8657a4ce2c1e37f660e47de84ff5fbeba01a0589af45350f6bdc26189"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}