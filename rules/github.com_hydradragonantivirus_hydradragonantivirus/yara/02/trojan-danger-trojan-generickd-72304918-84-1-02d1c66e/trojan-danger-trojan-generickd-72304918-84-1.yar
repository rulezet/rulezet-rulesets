rule Trojan_Danger_Trojan_GenericKD_72304918_84_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_84_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "520c756e6f0054b34ab4f9b35b80e03f505e83d57507e94c151af21a07833989"

  strings:
    $s1 = "8Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}