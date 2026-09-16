rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aikx1Om {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aikx1Om.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6463f3a245ce7203dd6fd794597b7896f0403b897de27792a4e6fa34c9e2a87"

  strings:
    $s1 = "RooL*/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}