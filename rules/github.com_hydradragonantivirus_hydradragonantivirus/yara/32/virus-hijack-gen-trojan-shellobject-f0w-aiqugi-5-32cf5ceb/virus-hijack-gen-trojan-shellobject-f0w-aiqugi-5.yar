rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5f1eeb6bcedac57bf33dc774af2ee69b94f202b3b4562a6d3ec0e7c28b6d0eb"

  strings:
    $s1 = "D4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}