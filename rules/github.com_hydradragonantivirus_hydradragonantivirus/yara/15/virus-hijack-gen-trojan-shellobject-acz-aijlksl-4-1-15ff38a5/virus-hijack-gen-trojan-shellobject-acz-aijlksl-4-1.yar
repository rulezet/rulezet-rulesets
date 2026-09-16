rule Virus_Hijack_Gen_Trojan_ShellObject_ACZ_aijlKSl_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ACZ@aijlKSl_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54914c4421753857cfbba66831a6c6a41c67289df7d113cae198bb3ff81f4bef"

  strings:
    $s1 = "Empty#mIP3P" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}