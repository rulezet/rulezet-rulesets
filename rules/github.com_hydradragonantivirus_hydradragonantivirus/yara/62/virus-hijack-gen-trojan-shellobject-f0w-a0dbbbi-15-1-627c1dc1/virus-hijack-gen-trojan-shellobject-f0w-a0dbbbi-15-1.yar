rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "488963efcbe4f55b704a35b6a924d2b619b85efabaedba853eed7fc60835e093"

  strings:
    $s1 = "Microsoft Company" fullword wide
    $s2 = "Microsoft Copyright (C) 2014" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}