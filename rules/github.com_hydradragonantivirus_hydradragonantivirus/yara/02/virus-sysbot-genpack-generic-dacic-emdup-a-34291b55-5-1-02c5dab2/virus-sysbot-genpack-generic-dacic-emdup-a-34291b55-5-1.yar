rule Virus_Sysbot_GenPack_Generic_Dacic_Emdup_A_34291B55_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_GenPack.Generic.Dacic.Emdup.A.34291B55_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1e1689b7c980aa13d86ae3dc61727ddfd455f6c23450e44df44f2f12e87a8d6"

  strings:
    $s1 = "bAYa):d1" fullword ascii
    $s2 = "AXIS]S" fullword ascii
    $s3 = "Sh(geM[HOiN]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}