rule Virus_Hijack_Trojan_GenericKDZ_103285_837 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_837.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fd976876446b982e13a72c5bdd704b5ee478c6c411b4b8fb57128e9ba0767c8"

  strings:
    $s1 = "`Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}