rule Virus_Hijack_Trojan_EmotetU_Gen_mS0_ha3oEjii {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.mS0@ha3oEjii.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ad604978a3f75c535821886e466b1e7745028a0a4cc112399ffddc779edc6db"

  strings:
    $s1 = "preagriculture" fullword wide
    $s2 = "Eudaemonism" fullword wide
    $s3 = "Slodge" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}