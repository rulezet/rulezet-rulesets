rule Virus_Hijack_Trojan_GenericKDZ_98113_48_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_48_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78d540b500d8756dd723ac849999fd1e005840554ee254c90a2cfb31164af75f"

  strings:
    $s1 = "tr{lOBo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}