rule Virus_Infector_Win32_Expiro_Gen_7_177 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_177.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de65a1e3895c53b2ab50b122845775c09ab1bd75d346b7e084ea200ddf37221c"

  strings:
    $s1 = "tabU}]%3w" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}