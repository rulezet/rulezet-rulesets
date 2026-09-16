rule Virus_Hijack_Trojan_GenericKDZ_98388_77_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_77_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2042a3640fc4998812cc4ae62ddce9a2cf62529e3b41f55963cf805292a23af9"

  strings:
    $s1 = "l_%MawK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}