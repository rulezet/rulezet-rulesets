rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4d227d0ff352fce003442b03889c86733f1e6d9cde64998e9253e4ebc2ccad3"

  strings:
    $s1 = "<hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}