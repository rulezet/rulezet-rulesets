rule Virus_Hijack_Trojan_GenericKDZ_103285_266_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_266_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61230819e5c29346c4b6e975b3a92f868b3ee64e11966b5a70061fb7ffffa2eb"

  strings:
    $s1 = ",Reference Viewing Condition in IEC6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}