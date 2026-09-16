rule Virus_Hijack_Trojan_GenericKDZ_103545_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5722d9b8973264865461dd303b57d4818293e5124e4b62b0dc3aac451366c142"

  strings:
    $s1 = "mYNa'f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}