rule Virus_Hijack_Gen_Trojan_ShellObject_CwZ_amBwvTb_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CwZ@amBwvTb_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "005984b57fc3c8c796fcf3e83a5dfc179c2bf80e272473d1d9bc95ea694c6373"

  strings:
    $s1 = "2(booL!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}