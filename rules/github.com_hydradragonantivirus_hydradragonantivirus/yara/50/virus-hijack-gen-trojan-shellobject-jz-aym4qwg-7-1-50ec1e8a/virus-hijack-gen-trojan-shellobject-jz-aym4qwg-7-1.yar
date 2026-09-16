rule Virus_Hijack_Gen_Trojan_ShellObject__JZ_ayM4QWg_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@JZ@ayM4QWg_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9df1902755bdab0cd48b4edb612d0c977578c9e92911db9680883e6209fca038"

  strings:
    $s1 = "EDDO&;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}