rule VirusShareTrojanSiggen533512_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen533512_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9924d8377f46b830b05dd98ed3274c5c937b5abd8ba5ef55a0b3ca2c4f702ad7"

  strings:
    $s1 = "Screen Spy " fullword ascii
    $s2 = "FastMM Borland Edition ?2004, 2005 Pierre le Riche / Professional Software Development" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}