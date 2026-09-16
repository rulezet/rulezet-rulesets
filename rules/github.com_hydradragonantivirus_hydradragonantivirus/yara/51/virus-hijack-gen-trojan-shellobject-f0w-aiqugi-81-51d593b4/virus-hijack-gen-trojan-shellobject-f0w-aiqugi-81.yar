rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_81 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_81.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daa3c9eb64f6321325e2af48857dcb9ac5b1534931b400174086981c7ac919a9"

  strings:
    $s1 = "G4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}