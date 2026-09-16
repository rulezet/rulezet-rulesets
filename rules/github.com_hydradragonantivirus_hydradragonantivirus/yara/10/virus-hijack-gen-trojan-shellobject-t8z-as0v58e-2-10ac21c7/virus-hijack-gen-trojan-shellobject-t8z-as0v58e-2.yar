rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aS0V58e_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aS0V58e_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ea78190948974bd6186e00308d255174f68045415776136325348ef1649f5c7"

  strings:
    $s1 = ". AQ!*XDm;DDm;^@#<MB9&COcO&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}