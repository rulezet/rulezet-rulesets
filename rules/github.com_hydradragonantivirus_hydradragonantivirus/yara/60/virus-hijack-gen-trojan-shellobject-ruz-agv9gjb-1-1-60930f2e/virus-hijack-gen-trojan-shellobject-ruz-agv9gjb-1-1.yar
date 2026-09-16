rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92557fa1ca60123749cc8d3f969c1ec4011b38d9759a719c2a812e8d64787984"

  strings:
    $s1 = "uW{Gump" fullword ascii
    $s2 = "R$ILly" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}