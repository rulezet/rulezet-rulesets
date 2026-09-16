rule Virus_Infector_Win32_Expiro_Gen_7_40 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d93b12ce3ec505b983467c79b06d06ed35411f4051237a557ca077b65a008d9a"

  strings:
    $s1 = "DEAf]A`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}