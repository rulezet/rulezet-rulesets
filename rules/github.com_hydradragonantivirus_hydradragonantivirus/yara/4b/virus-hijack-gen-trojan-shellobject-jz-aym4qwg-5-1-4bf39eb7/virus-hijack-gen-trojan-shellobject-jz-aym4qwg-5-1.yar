rule Virus_Hijack_Gen_Trojan_ShellObject__JZ_ayM4QWg_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@JZ@ayM4QWg_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5a276b823ae02ecac89790913aeb23a27b5bf72de4a0969fa273f2054f02b36"

  strings:
    $s1 = "BinO,V<i=o*" fullword ascii
    $s2 = "This pr9og" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}