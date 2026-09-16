rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b71b0c711eaaa987012cd4fdb50a6da345d92913d3936a1174aa15ae51baef4"

  strings:
    $s1 = "Action[*S" fullword ascii
    $s2 = "Style{(nS" fullword ascii
    $s3 = "PanCafe Pro Client Service" fullword wide
    $s4 = "{ross&%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}