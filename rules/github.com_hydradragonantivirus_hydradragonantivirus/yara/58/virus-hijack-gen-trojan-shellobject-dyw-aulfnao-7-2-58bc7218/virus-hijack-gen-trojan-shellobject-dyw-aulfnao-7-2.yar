rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c798a327ca2bfcb8b1182462ced1325bf518cb5cb608800c33bd81c4c4b0a"

  strings:
    $s1 = "J!SOaR`)6rg" fullword ascii
    $s2 = "d!hooN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}