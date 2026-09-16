rule sig_20160824_56c31e5af12638b5714edaab270f0e30 {
  meta:
    description = "datamaliciousorder - file 20160824_56c31e5af12638b5714edaab270f0e30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b348398dd030f25a3447ddb48361d1e5d27b8a1329917c385db66016ed7d34"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}