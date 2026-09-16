rule Trojan_Autorun_Backdoor_Hupigon_AAAH_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Backdoor.Hupigon.AAAH_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9b92a51cbda37e77358712cf2127b6c9437d8f67a7860631875ef88e3c06dfe"

  strings:
    $s1 = "Copyright (C) 2014 Gydftgfefef" fullword wide
    $s2 = "Copyright 2014 XiongHaret" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}