rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a4f8c91fc4397348ebaf99c8b93dfb87915f2c0bfcbb61b4bade1e6e9e4e2ee"

  strings:
    $s1 = "44. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}