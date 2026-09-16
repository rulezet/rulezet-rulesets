rule Virus_Sysbot_GenPack_Trojan_GenericKDZ_94923_6 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_GenPack.Trojan.GenericKDZ.94923_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c31c18f8e4bb144b6b4454ecaaffcf359ff67dfb4f4a9ac9fcad5abb4d9d6efb"

  strings:
    $s1 = "oleo!X" fullword ascii
    $s2 = "s)oVey" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}