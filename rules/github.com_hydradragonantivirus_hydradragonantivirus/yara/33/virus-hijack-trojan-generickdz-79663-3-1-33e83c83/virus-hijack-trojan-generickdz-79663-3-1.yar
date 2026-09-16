rule Virus_Hijack_Trojan_GenericKDZ_79663_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3f0edddbf95daf9262526998c913aabcd384cf22804e7113bd88f1319d96c69"

  strings:
    $s1 = "{j`cOrA" fullword ascii
    $s2 = "cHUB@." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}