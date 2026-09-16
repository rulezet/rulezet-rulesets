rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d6b4f70edce42c5f59bb826f67c9831a119f1ac3847c5835a5464a58385d3bb"

  strings:
    $s1 = "j'Computer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}