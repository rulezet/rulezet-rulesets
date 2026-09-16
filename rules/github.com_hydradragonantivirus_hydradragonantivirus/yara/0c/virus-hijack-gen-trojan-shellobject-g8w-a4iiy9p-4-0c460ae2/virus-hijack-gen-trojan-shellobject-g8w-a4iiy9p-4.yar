rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4304b2ea81588d51b2e781c525ad0cc46a8618c25f6f14691635a21923ca419"

  strings:
    $s1 = "[Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}