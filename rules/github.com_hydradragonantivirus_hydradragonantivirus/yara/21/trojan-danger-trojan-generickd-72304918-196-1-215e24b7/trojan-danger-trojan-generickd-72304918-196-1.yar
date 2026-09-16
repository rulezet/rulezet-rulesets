rule Trojan_Danger_Trojan_GenericKD_72304918_196_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_196_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55f2238fcc65b7381c665f7f1240d266d2c50982bb2f1fd4ebf2576ab178d4e1"

  strings:
    $s1 = "$Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}