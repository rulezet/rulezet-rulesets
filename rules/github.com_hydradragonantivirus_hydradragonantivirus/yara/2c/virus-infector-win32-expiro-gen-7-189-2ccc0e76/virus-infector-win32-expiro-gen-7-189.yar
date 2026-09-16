rule Virus_Infector_Win32_Expiro_Gen_7_189 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_189.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef6a1f5e4daa59ba651bab0238f86fe643b507a870f5d0253c6afed48b5ae482"

  strings:
    $s1 = "TeAM[=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}