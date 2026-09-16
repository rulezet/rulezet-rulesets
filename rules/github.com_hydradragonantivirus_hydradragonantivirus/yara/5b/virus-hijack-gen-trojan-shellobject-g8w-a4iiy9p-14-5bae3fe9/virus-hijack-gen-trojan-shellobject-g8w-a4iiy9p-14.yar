rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c92b1310d7b5727d2b39dd7b1963db495580d6a0e8d128f7fbf26696109764a8"

  strings:
    $s1 = "2eSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s2 = "2eSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}