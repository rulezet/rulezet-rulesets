rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_aqH1LVc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@aqH1LVc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "706ff2471b96fe14e5c7f107d308548efa53f53f4b5e7ef2d0cdf6cadae40408"

  strings:
    $s1 = "2must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}