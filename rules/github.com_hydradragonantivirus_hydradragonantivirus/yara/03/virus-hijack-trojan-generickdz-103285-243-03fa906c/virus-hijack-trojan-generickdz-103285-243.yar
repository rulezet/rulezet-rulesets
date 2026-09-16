rule Virus_Hijack_Trojan_GenericKDZ_103285_243 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_243.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abf1ede0baf1d2af05faae2f10c882716140ec6acecd6f07c17f936f0e60c07c"

  strings:
    $s1 = "$Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}