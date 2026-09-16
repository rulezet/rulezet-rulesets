rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aOGzovi_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aOGzovi_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3125213859b6058f79e48bb29f4ab1cbf2ba64e4daa5141a89b35271d2e4e30e"

  strings:
    $s1 = "\\.Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device th" ascii
    $s2 = "\\.Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device th" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}