rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d2ac87c3e052577e7dcbc18c7ee0ed00c1d6aeb69f22700cd25933c8dc2885a"

  strings:
    $s1 = "6IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}