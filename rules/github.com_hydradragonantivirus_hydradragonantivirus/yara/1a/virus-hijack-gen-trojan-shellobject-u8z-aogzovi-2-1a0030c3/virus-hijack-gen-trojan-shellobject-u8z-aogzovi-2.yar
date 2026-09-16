rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aOGzovi_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aOGzovi_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c79a7cdfc86ec64d4122c4b3da37b57157a2f1a3f8e04f1132de93e7cd7d1f3"

  strings:
    $s1 = "cSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}