rule Virus_Hijack_Trojan_GenericKDZ_98113_406_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_406_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05ff140fe4e4feed860505d7b1be062d5cd05d6d54f6ccab50b04d30f02b3d5f"

  strings:
    $s1 = "GAmp:-1" fullword ascii
    $s2 = "}|%BREt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}