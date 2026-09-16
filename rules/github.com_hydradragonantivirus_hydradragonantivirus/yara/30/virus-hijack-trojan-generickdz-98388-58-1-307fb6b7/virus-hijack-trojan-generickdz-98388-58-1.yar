rule Virus_Hijack_Trojan_GenericKDZ_98388_58_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_58_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0443bf87644bfa525ababc4aa795aa1eda7c62cffe9c102d83c47bf88559fafd"

  strings:
    $s1 = ": SEeP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}