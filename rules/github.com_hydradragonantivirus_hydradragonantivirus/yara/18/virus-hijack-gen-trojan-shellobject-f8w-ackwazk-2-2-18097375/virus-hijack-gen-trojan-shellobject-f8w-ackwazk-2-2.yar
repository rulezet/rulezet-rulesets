rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCkwazk_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCkwazk_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d1f17a978f3a0593b020a2c6a2a7fac94cf955d60990227bb43c1748c50150f"

  strings:
    $s1 = "!ze< CRAN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}