rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2ececa9e22adff16b5b0c304bfe80973073e3e5f7ac0c787b96e755adff9a04"

  strings:
    $s1 = "Shrieval" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}