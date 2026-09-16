rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c5d8ca65ef62ae274bd89194589fc92e4077b92451f2d64ee75948dcb794248"

  strings:
    $s1 = "'Computer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}