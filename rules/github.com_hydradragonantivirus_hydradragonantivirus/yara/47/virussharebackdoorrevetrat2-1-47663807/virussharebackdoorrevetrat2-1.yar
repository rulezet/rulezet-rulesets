rule VirusShareBackDoorRevetRat2_1 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorRevetRat2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab561032327d25263d4e395d95659b682825d23e7df71bc979ac1ab8c022d7e3"

  strings:
    $s1 = "c:\\users\\qrt\\documents\\visual studio 2013\\Projects\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}