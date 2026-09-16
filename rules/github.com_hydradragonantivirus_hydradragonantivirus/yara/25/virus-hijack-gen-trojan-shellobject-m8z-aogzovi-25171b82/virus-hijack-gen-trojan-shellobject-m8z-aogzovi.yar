rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aOGzovi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aOGzovi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f5be5f74a38be74bc29fa60d5178dc3c916265ff078334f85bf99441c8018d6"

  strings:
    $s1 = "_Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}