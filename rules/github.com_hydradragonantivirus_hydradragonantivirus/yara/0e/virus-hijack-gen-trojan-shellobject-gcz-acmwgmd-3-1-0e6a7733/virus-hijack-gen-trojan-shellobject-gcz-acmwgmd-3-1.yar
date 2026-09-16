rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6415b1e634f971766db7ee721cdd487df982cfb17768bb8a694e5a8a9b351dab"

  strings:
    $s1 = "Claret" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}