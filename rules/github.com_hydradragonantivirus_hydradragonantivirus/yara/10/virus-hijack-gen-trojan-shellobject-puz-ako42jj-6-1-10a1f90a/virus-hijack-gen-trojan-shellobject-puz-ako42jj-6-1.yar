rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "488bb69b6f11e238ba05ca9daec280b830e921c7c7390ecb3deb2bd21aee19fe"

  strings:
    $s1 = "ream]i5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}