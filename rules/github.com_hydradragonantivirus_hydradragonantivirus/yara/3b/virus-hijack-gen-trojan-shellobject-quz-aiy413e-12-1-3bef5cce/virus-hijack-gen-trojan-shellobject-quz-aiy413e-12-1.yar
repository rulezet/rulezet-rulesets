rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fccd825dc88ec2f564ede7ce270143826a66a91e102786aa9916322baf5934c2"

  strings:
    $s1 = "C#);mIff" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}