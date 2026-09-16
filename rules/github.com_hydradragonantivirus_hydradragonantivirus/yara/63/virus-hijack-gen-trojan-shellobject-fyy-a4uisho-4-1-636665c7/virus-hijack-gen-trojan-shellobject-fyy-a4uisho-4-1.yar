rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "707b8be1a93263cc7d4440ee7353346a3ba96f37fc1bffc4d506f07eb180acc6"

  strings:
    $s1 = "EboE Xk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}