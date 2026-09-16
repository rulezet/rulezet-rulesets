rule Virus_Infector_Win32_Expiro_Gen_7_206_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_206_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2944fc30ca69e6026d17aa97552d5fd9b1424abcdf57e68bdc7adb83ebcf22bb"

  strings:
    $s1 = "<author name(s)>" fullword wide
    $s2 = "<company name here>" fullword wide
    $s3 = "The driver for the supercool driver-based tool" fullword wide
    $s4 = "Copyright ? 2011 <company name here>" fullword wide
    $s5 = "Supercool driver-based tool" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}