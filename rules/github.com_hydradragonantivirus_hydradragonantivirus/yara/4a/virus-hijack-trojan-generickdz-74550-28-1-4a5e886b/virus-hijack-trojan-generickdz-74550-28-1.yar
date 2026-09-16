rule Virus_Hijack_Trojan_GenericKDZ_74550_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6de2bc0f0885cbec92f25216d89a072c36d28f0549583939db05114ac41248a"

  strings:
    $s1 = "masK%bJ" fullword ascii
    $s2 = "oMAo'%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}