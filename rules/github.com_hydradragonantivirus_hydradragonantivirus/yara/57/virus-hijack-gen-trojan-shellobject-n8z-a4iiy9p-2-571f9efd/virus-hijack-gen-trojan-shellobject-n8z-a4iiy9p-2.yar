rule Virus_Hijack_Gen_Trojan_ShellObject_n8Z_a4IIY9p_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n8Z@a4IIY9p_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc1657f2f45e7b1d5acfe071d00b13e0a2d44ee188701031b14f3eeb698526a3"

  strings:
    $s1 = "_Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}