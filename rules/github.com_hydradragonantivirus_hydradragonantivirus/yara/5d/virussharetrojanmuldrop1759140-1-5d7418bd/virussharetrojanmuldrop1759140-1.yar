rule VirusShareTrojanMulDrop1759140_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanMulDrop1759140_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bed0a8c5f5760ede547a9c559f14787dd738e0c70ecc125b2300ce111005436"

  strings:
    $s1 = "KAHA,-n" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}