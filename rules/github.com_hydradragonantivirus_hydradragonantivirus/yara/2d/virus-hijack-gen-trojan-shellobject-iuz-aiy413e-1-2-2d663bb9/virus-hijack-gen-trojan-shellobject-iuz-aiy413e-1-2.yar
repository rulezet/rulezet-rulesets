rule Virus_Hijack_Gen_Trojan_ShellObject_IuZ_aiy413e_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43ba08e730449e9bfb2403f2c38f2c0a7af1a668618ea2e3dbd30a6d638bb995"

  strings:
    $s1 = "Trow,r" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}