rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aag1Gcl_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aag1Gcl_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f2cd6bda846a9ded45a701fc7059a0c080fca566ace0d14d8f09e25bbf54e6a"

  strings:
    $s1 = "CHAIN[Q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}