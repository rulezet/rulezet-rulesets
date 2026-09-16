rule Virus_Hijack_Trojan_GenericKDZ_98113_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc495877c0de89f240cfa90c34d505469b84c2990f71bdf4f0dabde4e27b73e8"

  strings:
    $s1 = "Thug#A`A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}