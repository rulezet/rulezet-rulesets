rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_aKo42Jj_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "775eb2ea85a708ec2d2ee8ad9f52615c2107823fc3fc076035e5723975038277"

  strings:
    $s1 = "soft Visual StudQn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}