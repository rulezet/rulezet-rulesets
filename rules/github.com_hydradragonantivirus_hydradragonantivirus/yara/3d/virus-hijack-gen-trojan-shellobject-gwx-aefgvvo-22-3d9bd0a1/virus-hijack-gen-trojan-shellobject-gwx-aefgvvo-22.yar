rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50e09984c4ecb218b8e0def7bb3a4e459e8444add5d99a676ba535560b6dee80"

  strings:
    $s1 = "~)DUmA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}