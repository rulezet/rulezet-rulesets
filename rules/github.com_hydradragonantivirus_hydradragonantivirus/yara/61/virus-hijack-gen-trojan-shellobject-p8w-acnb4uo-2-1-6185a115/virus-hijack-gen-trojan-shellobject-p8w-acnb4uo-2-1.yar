rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_aCNb4Uo_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7f1fce680a3ff7f569e687a3ca2719d241705e2b1dfd0158a8a03e2913d9503"

  strings:
    $s1 = "BUrn,Ru" fullword ascii
    $s2 = "CORE;5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}