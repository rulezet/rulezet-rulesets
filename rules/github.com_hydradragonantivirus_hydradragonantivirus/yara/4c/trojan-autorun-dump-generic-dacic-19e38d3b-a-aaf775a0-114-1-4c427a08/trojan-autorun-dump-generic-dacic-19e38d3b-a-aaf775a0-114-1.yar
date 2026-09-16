rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_114_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_114_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "803cf958e1cd34c4aae717420ef6953b671155cd43a282605e33722756eab3dc"

  strings:
    $s1 = "KNOW*A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}