rule Virus_Hijack_Trojan_GenericKDZ_99416_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98a30f14a3e520141c016837575c9a953a5eca083ecaae7963367890c5e9bf90"

  strings:
    $s1 = "sN}PesA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}