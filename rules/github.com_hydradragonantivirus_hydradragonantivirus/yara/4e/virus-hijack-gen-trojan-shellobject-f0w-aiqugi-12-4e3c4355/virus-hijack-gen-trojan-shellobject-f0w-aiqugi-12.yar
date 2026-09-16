rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20637b7170499a960d726e0c7d5747a51744067455eed0266b9e1638140d45c3"

  strings:
    $s1 = "lm4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "$rAzz," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}