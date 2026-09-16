rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCMzZah_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCMzZah_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e35b41536a44ae5eb040a70c8eca2eb1cd2a372428a91c9d3f51f3928ff57545"

  strings:
    $s1 = "Fistular" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}