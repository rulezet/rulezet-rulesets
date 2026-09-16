rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_a4IIY9p_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@a4IIY9p_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3dc12f9b55cbffc7036943106628c265b634083a51a8cf8ac4ac5d24d4c072a"

  strings:
    $s1 = "LSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}