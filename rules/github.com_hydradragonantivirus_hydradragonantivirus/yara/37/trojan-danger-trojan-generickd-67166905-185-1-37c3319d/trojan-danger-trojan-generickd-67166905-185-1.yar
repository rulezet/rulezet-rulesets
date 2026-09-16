rule Trojan_Danger_Trojan_GenericKD_67166905_185_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_185_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aefba02413124aea828e6f5dd0366a1cbd0d10e4ebf33b573e32086018cb57f5"

  strings:
    $s1 = "3Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}