rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f50e421130e1d425dbea4a823569a8028212847a82620dae922215621363eb64"

  strings:
    $s1 = "b4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}