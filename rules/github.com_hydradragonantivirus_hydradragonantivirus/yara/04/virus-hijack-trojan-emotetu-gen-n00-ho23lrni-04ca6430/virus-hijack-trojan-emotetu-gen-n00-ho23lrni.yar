rule Virus_Hijack_Trojan_EmotetU_Gen_n00_hO23lRni {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.n00@hO23lRni.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15add70c82ab38d0781cc8e684045c079c188ebd1df17e01ee1bd9122776e9e"

  strings:
    $s1 = "underfeeling" fullword wide
    $s2 = "Morrowmass" fullword wide
    $s3 = "Abstractiveness" fullword wide
    $s4 = "HALA@ED" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}