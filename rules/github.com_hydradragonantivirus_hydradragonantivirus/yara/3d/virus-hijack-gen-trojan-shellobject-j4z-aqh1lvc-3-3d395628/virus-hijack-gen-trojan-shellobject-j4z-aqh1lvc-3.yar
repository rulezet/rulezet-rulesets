rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65b785c2d6f85f5cd31c654f2670dcf1bc470f7a1fbfe73870afac822a396511"

  strings:
    $s1 = "pmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}