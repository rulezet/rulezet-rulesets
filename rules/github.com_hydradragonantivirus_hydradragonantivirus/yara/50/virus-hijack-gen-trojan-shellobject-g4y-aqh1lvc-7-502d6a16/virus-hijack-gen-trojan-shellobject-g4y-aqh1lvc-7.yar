rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_aqH1LVc_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@aqH1LVc_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeb808321861bb00319683fa1e3cd381a34e90385b001601c1f03c7942ab3946"

  strings:
    $s1 = "Nmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}