rule Virus_Hijack_Gen_Trojan_ShellObject_vyZ_aSgChKg_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.vyZ@aSgChKg_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10ef22173f24191bb914d7c3819f1a3fdfc3ee1dcee79d4ebc6bb17cf97d7b25"

  strings:
    $s1 = "duLL:_L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}