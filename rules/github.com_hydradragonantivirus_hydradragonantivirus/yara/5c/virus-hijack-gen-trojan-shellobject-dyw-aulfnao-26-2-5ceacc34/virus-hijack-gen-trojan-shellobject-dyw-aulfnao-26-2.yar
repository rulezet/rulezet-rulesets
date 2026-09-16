rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_26_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_26_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "528f61c9064ef000582ceda0d65d3ad694d3422b86a2d15d0c98d37b07b699dc"

  strings:
    $s1 = ">?NiDe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}