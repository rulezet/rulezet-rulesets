rule Virus_Infector_Win32_Expiro_Gen_7_65 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_65.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "053594710e356bedb068809dbb0d5341735cb69e06719278bc872b73e3188a68"

  strings:
    $s1 = "LEAM}<_" fullword ascii
    $s2 = "VERd?>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}