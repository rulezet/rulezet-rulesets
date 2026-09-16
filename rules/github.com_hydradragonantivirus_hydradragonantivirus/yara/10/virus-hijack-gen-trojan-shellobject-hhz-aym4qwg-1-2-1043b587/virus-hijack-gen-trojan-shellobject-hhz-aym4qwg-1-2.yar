rule Virus_Hijack_Gen_Trojan_ShellObject_hHZ_ayM4QWg_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.hHZ@ayM4QWg_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58dbf7704f1b5a9f6d3b674360d4ee0154a7bf87a645b43933d2db099967f309"

  strings:
    $s1 = "X:PluD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}