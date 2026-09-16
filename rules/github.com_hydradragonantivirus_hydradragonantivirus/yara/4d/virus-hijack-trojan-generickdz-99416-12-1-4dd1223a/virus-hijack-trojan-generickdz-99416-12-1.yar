rule Virus_Hijack_Trojan_GenericKDZ_99416_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04bb5f771c7fdce48dd04b23621283bca6087b714946bb9837c6e1b5b4e59983"

  strings:
    $s1 = "W{MokI" fullword ascii
    $s2 = ",\"yArk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}