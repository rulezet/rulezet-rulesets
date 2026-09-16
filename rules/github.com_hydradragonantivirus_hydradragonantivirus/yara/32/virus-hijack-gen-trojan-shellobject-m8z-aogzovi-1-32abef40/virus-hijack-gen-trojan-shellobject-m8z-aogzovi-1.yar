rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aOGzovi_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aOGzovi_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ad68edb10ccbe99c6ab1cb62679cc8981dcf0f72dfdf2c691c9be052d7c5bed"

  strings:
    $s1 = "HSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}