rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aSgChKg_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aSgChKg_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4896ad7849059deff517e9b1272c69d2690a55cf85b57dfea48945d6b5a9699"

  strings:
    $s1 = "Portions Copyright (c) 198" fullword ascii
    $s2 = "time e/)" fullword ascii
    $s3 = "' (WORKS!!)_" fullword ascii
    $s4 = " Xs;FOCUS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}