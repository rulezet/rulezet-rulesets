rule Virus_Infector_Win32_Expiro_Gen_7_19 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c280f90d5e019523e419f39be7af94a844b2ad4e52d319b0fbc390347588975c"

  strings:
    $s1 = "miCO>@4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}