rule Virus_Hijack_Trojan_Agent_DQQO_375 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_375.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6337db07ec2d4092b7b2b1fd3fcba6ff96f2eb5f174cdce08312059837d0aaec"

  strings:
    $s1 = "IProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}