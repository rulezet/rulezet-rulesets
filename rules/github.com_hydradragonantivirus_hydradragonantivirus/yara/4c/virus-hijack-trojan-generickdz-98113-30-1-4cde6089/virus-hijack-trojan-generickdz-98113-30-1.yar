rule Virus_Hijack_Trojan_GenericKDZ_98113_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbc7c4d990662386920eb50b082629e2b3539f11b0739ce8c7ea5605c24c86f6"

  strings:
    $s1 = "Peda;0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}