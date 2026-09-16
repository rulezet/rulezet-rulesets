rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_aKo42Jj_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e57f2bdccd2882f6f13b194ee7485a6a963fb5a828ae13c0093bbc800fddaac7"

  strings:
    $s1 = "soft Visual StudQn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}