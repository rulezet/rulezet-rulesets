rule Virus_Infector_Win32_Expiro_Gen_7_180 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_180.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3231c6973eef5fbfc63f08dac15c12528144e1fa7ea8f2c33286ae8e8afeaa2b"

  strings:
    $s1 = "LEAM}<_" fullword ascii
    $s2 = "VERd?>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}