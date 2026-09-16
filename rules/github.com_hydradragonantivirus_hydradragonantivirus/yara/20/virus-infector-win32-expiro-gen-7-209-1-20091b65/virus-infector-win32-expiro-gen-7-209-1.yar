rule Virus_Infector_Win32_Expiro_Gen_7_209_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_209_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17dc4448c8e8b6b096e0a9478d10b532fda9acc272f2febab676758556930baf"

  strings:
    $s1 = "Rockwell Collins save" fullword wide
    $s2 = "Copyright 2016 Rockwell Collins save" fullword wide
    $s3 = "Rockwell Collins Midwest Communications" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}