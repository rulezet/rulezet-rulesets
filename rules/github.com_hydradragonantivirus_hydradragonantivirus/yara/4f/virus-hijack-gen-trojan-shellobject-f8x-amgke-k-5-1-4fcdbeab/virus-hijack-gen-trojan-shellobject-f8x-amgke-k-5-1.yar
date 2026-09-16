rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_amgke_k_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "377e357791cbce4206218a896d18ad91c8ab18a751b345ed151f18de00bf02c1"

  strings:
    $s1 = "Copyright (C) Buidgtre" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}