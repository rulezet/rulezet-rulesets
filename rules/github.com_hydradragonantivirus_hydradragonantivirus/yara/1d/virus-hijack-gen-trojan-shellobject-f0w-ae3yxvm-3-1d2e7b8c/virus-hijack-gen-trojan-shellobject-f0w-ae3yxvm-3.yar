rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4225c52561c30a7f05350da051b78cb3ba47e5c0fda0581adb644a0f40587e17"

  strings:
    $s1 = "r74. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}