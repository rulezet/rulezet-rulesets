rule Virus_Hijack_Gen_Trojan_ShellObject_IuZ_aiy413e_15_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IuZ@aiy413e_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a402fe170255293833ae45a1647e140581f0dac01e1342113afbd38ebf4330"

  strings:
    $s1 = "dupE`cl*" fullword ascii
    $s2 = "dupe`cl*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}