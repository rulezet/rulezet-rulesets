rule Virus_Hijack_Trojan_GenericKDZ_98113_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56d753298b7bc137eb6a412c48604cd292ca048c0a4268d52dc8d9443c827e69"

  strings:
    $s1 = "F;FIzZ" fullword ascii
    $s2 = "p%WiPe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}