rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acabc27a29d1d15c37e9b9cdca6a38f5cd51bb9937b5a34c3be0a4bcca8c2af8"

  strings:
    $s1 = "%YComputer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}