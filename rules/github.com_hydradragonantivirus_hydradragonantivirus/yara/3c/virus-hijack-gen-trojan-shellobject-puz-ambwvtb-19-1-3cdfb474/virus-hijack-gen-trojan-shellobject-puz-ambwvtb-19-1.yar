rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9a75771176c18bca5da07aef8323a24decafe43a68237aa965d0305c90b8e15"

  strings:
    $s1 = ";}hinT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}