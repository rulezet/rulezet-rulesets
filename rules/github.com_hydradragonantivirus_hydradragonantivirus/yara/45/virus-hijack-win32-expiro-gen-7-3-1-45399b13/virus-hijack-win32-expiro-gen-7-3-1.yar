rule Virus_Hijack_Win32_Expiro_Gen_7_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Expiro.Gen.7_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d40b2fbe2c32e010f08ad6d1e287882c394b1a66ae779caa69e4c2668059c1f8"

  strings:
    $s1 = "Fulk<>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}