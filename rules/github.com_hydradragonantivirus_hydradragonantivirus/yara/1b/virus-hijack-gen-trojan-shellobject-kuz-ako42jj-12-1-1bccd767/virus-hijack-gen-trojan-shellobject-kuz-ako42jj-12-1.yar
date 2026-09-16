rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_aKo42Jj_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e672528ac29167ae49204c27a1a7d4d94f03b0bef9115f719bd5026bed8f1e5b"

  strings:
    $s1 = "W9(>joUg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}