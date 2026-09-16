rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "192b3d2b82636a980b1a36515a58d0791d4f3dd975b0441da48ac3da01d8a549"

  strings:
    $s1 = ";|4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}