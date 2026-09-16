rule Trojan_Danger_Trojan_GenericKD_67993768_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67993768_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8467673fcaab1578f981c7b17d3f6cec51bc4070be9cbd2c4820ba1fb9c1d02"

  strings:
    $s1 = "lSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}