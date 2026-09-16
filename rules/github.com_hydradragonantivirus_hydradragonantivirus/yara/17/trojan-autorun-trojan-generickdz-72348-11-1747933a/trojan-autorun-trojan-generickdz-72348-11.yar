rule Trojan_Autorun_Trojan_GenericKDZ_72348_11 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44a2f1d3bcb7d47158244349ce28ca273eeda5e27ce2c04f1c7b233763b50bcb"

  strings:
    $s1 = "acknowledge that you will create and activate an administrator account and password and that the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}