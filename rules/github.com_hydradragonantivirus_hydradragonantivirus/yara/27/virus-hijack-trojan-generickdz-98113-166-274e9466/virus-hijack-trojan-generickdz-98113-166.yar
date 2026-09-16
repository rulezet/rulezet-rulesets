rule Virus_Hijack_Trojan_GenericKDZ_98113_166 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_166.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37e453be75312a01fb0978f403e5f30584a5d80d998598f97e8e03dff529a756"

  strings:
    $s1 = "Pfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}