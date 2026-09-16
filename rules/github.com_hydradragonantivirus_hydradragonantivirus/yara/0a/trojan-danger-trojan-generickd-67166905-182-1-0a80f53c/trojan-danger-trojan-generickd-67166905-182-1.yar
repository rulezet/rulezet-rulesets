rule Trojan_Danger_Trojan_GenericKD_67166905_182_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_182_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02c89d88b33dc777b59061d9416a65e158993a703d60cc0872d775b147cc9f69"

  strings:
    $s1 = "\"wSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device th" ascii
    $s2 = "\"wSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device th" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}