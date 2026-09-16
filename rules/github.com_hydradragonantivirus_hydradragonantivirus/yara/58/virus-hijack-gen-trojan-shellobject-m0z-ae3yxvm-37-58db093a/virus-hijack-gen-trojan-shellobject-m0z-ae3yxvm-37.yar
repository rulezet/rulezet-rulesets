rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_37 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_37.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d69c06a750f16a9205ba5a67b63511cd576af300b35ee2792306ee322e1e514"

  strings:
    $s1 = "5D4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}