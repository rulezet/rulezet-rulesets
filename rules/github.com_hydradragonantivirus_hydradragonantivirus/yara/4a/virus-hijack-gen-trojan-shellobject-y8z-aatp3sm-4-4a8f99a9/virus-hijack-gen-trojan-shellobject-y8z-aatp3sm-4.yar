rule Virus_Hijack_Gen_Trojan_ShellObject_y8Z_aatP3Sm_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.y8Z@aatP3Sm_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd41a15fc2a678e79609fc4372f9fdb6544077910ee8b6a10cf53cb18e5bd606"

  strings:
    $s1 = "viER*%b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}