rule Virus_Danger_Gen_Trojan_ShellObject_eGW_aCQuMlp_2 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.eGW@aCQuMlp_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed70ba4b976280b461546093d1bbc1736dd524f92dfd83f94c8e2d4c81c17fa0"

  strings:
    $s1 = "snub(." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}