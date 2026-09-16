rule Virus_Infector_Win32_Expiro_Gen_7_145 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_145.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8900e7a9d45cddc15b38c9770fe2a38868326036be238b94f17eeda123e072bb"

  strings:
    $s1 = "n#welK" fullword ascii
    $s2 = "':deRe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}