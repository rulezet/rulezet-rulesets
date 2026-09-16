rule Virus_Hijack_Gen_Trojan_ShellObject_g0W_a4_lcVd_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ca17831f222b001c8916ce4a448d65ea679cee48cc75a519d6b73e0d97e75a0"

  strings:
    $s1 = "N\"Piso" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}