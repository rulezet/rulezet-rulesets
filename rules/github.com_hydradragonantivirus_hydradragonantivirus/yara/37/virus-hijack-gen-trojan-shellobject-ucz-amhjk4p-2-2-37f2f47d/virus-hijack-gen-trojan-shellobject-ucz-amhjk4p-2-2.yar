rule Virus_Hijack_Gen_Trojan_ShellObject_uCZ_amHJK4p_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uCZ@amHJK4p_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6edafb419c3860b27129ff91d6fd09334e494d4c315271a7964fbc5527a6263"

  strings:
    $s1 = "AutoIt v3 Script : 3, 2, 4, 9" fullword wide
    $s2 = "GYPS?;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}