rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_aWZUE8k_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@aWZUE8k_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dae7f239363e693f712ae796c1b4878dd5d4235dcbaaf47328b798df266c77fd"

  strings:
    $s1 = "toLu$k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}