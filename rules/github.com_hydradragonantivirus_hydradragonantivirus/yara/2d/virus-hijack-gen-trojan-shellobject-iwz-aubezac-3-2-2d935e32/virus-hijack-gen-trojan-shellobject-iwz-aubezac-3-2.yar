rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "430e3f9998de6900b60739bc792dcade755bf8e1734ef7c173acc53dbedaae03"

  strings:
    $s1 = "=)bAsh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}