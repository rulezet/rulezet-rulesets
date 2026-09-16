rule Virus_Hijack_Trojan_GenericKDZ_98388_202_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_202_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a781eaec8b74f722dadf1e76dac7cbc2e35c2dfe3e39b8ca5e3c3607ec44ed1b"

  strings:
    $s1 = "naoS{m8" fullword ascii
    $s2 = "SLuD[6" fullword ascii
    $s3 = "BoaR}E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}