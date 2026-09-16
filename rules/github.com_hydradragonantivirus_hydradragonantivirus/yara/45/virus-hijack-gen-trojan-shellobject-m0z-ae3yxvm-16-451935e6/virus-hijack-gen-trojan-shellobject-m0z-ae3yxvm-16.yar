rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ea31288254abe3d2c720ae39733ef91f1537292dde3b5d881244a1f40bf4f5e"

  strings:
    $s1 = "H4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}