rule Virus_Infector_Win32_Expiro_Gen_7_99 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_99.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c34d933596a56bdf2660f8b4a1b71f8ce0eae490509b8a1a3436fda74a9949f"

  strings:
    $s1 = "*epHa?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}