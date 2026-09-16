rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_aKo42Jj_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5857314c3aaa07875286eb7af8bb235b7575c305c90d1a042a48ba15b3a14229"

  strings:
    $s1 = ".s|16zPQSYe#furY%TX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}