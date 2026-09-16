rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46023ea072054bdc5a544fab5cfd84f0b81873c98a1b21b7e93533df28bf4125"

  strings:
    $s1 = "KJIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}