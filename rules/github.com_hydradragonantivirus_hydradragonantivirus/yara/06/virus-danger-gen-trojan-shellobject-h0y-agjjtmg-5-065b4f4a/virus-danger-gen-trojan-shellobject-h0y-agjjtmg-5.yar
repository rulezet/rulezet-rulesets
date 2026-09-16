rule Virus_Danger_Gen_Trojan_ShellObject_h0Y_aGjJTmg_5 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.h0Y@aGjJTmg_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b942bd2fd78979bd6c123deb43d1ec8af18b2399e347dcf8598325da44b37532"

  strings:
    $s1 = "&authorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}