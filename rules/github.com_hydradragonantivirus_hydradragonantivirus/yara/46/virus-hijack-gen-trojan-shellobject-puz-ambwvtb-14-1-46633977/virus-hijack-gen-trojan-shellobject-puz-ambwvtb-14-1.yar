rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c143d1fe5a322cdc4f280474872fcecb062a5c940751dd0ba0fa1d0f08b43271"

  strings:
    $s1 = "G[adAw" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}