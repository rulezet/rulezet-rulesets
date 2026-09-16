rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ae0D4Vj_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ae0D4Vj_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a90d37d2110d341c580c770654073993161d9f6f900f2b66cab008a0a8f4a679"

  strings:
    $s1 = "/a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}