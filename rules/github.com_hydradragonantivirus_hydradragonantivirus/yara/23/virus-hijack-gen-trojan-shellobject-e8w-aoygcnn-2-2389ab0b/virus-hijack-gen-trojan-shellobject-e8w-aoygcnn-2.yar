rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cf23b5df6de2be6c4773b9188e6b19772851047da1fd86f901db2648b55d073"

  strings:
    $s1 = "Lhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}