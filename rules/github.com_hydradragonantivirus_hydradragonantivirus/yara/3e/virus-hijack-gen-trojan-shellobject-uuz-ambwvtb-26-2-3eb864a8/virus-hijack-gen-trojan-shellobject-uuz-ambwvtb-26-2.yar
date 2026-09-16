rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_amBwvTb_26_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@amBwvTb_26_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "812da47e05caddc0aa56918e096691c3afdea23f29d037eb21241d5999753f77"

  strings:
    $s1 = "Flicks Training" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}