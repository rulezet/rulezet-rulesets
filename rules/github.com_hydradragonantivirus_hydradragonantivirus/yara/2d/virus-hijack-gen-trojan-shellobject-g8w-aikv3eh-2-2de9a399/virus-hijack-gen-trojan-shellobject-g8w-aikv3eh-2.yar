rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiKV3eh_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiKV3eh_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f22893b328691c0746bf4cdc3fbc74f6a64d5da046f3de2c35a644c6c7be928"

  strings:
    $s1 = "|Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}