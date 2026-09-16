rule Virus_Hijack_GenPack_Backdoor_Hangup_B_167 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_167.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e86c5165960d66498f04e7ab91e2768203ede8d0c2c448fac7b224c7a254c54"

  strings:
    $s1 = "9*Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}