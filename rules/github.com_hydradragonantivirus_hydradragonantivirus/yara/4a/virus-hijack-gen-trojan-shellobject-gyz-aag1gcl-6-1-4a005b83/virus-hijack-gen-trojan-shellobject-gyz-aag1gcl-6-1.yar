rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aag1Gcl_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aag1Gcl_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "756f2e26cf757979dd435713e136b127448bd739d593a5efdbadcdef62a665be"

  strings:
    $s1 = "Socialism" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}