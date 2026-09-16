rule Trojan_Autorun_Trojan_GenericKDZ_94847_125_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_125_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76ba120e84ec172611cdcd45279328852aa43d919ebcbb4e936db488ba1e185a"

  strings:
    $s1 = "NProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}