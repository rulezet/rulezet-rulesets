rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17cb7ab4d2f5483254e6454204d5222fb072d25afa958a20c5d24f6b8eaa68ba"

  strings:
    $s1 = "Service Host Process" fullword ascii
    $s2 = "Exception<S@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}