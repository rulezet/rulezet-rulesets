rule Virus_Hijack_Trojan_GenericKDZ_74550_84_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_84_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78fbe7d6329a195a70adfe0da3ce7ef40824c4ba43b8e48d4220aee21015ac54"

  strings:
    $s1 = " )MIrO)~vs5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}