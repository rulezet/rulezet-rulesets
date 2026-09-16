rule Virus_Hijack_Trojan_EmotetU_Gen_nW0_hGXk9doi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.nW0@hGXk9doi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "175b3757b8c356a264c3c3a079596063e2b9c4f731e23fb490aed1b3fbca44bf"

  strings:
    $s1 = "opacate" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}