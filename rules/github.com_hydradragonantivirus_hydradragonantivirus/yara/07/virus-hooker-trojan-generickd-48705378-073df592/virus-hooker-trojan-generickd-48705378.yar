rule Virus_Hooker_Trojan_GenericKD_48705378 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.GenericKD.48705378.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae2e058aa0f3c69191bd1982d538617e1b7601afc49c28f93334a55075888adc"

  strings:
    $s1 = "Exception R@" fullword ascii
    $s2 = "OctoberInvalid variant type conversion" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}