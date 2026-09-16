rule Virus_Hijack_Trojan_GenericKDZ_105924_303_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_303_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56fb863ff2f43d35fb82f0193487fcd1eb1becde08c5951c0b9987dbddc5c810"

  strings:
    $s1 = "GAby`S" fullword ascii
    $s2 = ",\"froG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}