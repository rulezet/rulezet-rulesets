rule Trojan_Danger_Trojan_GenericKD_72304918_55_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_55_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a182ba2b5cc72b6fb7bdb374dc138f2ca633e73b07cbfcf27885ad3ab0f2d070"

  strings:
    $s1 = "NSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}