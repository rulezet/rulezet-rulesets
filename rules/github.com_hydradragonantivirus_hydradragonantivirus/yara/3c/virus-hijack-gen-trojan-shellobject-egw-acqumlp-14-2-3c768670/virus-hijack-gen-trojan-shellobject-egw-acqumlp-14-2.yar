rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12b6c4aca8af6a0bf15e9278d47a66ef8c7f2772e4b5e863e6bb64289dd47837"

  strings:
    $s1 = "Profiler detected" fullword wide
    $s2 = "Loop broken" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}