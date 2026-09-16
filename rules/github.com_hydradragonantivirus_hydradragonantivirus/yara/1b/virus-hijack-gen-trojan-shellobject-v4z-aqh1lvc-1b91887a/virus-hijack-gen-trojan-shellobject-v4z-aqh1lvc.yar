rule Virus_Hijack_Gen_Trojan_ShellObject_v4Z_aqH1LVc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v4Z@aqH1LVc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d22c82f9e04d304cad3560f8991da2a6f8226e117740e25d202d09f7813a12bd"

  strings:
    $s1 = "+<must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}