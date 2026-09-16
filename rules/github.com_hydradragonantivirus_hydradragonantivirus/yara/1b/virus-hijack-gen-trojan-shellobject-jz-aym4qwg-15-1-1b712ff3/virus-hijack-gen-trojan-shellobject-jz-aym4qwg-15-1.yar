rule Virus_Hijack_Gen_Trojan_ShellObject__JZ_ayM4QWg_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@JZ@ayM4QWg_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2f9308e65f8d394cb33f00603ebdccae665ffc5822afb61dc3224fc157ff76c"

  strings:
    $s1 = "frownful" fullword wide
    $s2 = "conservant" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}