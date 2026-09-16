rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0447416911940dc9ca9feee2683098e24b95608cae4351c58188713b5ef6e01"

  strings:
    $s1 = "=<DyAD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}