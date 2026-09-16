rule Virus_Danger_Gen_Trojan_ShellObject_iuZ_amBwvTb_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.iuZ@amBwvTb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c162837b7cfdcdadae40a406ecf12b70564be1eb01028b44b643de6d46156fc8"

  strings:
    $s1 = "TRap?<nau" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}