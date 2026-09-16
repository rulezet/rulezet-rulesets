rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4576cef4b8507bab6ce4232232deecf7dce239f50519029dce19a89dedd20173"

  strings:
    $s1 = "sToT)." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}