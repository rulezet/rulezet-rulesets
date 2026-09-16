rule Virus_Hijack_Gen_Trojan_ShellObject_f4X_aqH1LVc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f4X@aqH1LVc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84be0ffbda119e86cbd7a250c942de7a5c39e3993db9d4a0c42d57e3535537c9"

  strings:
    $s1 = "\\must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}