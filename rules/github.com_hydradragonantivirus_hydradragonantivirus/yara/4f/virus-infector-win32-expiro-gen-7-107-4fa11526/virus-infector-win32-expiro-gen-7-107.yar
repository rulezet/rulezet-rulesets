rule Virus_Infector_Win32_Expiro_Gen_7_107 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_107.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502cbe2f0a1f2a8580fb47ac985c482197fa714f0421db376d7705f3ab0f52c8"

  strings:
    $s1 = "TeRA{.0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}