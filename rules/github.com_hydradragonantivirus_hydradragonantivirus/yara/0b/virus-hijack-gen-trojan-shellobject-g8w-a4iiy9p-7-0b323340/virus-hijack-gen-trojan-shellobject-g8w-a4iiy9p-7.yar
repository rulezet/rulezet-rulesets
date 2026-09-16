rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbcd02920138f4aadfb45ddd24485e3e837b32b001de93b63efea1157843b84d"

  strings:
    $s1 = "zySubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s2 = "zySubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}