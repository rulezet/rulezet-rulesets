rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8292c45f1ade56cabe49a75f76abd544340fc44ae57197455c85715452beeeff"

  strings:
    $s1 = "L`RACE]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}