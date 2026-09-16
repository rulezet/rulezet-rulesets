rule Virus_Hijack_Gen_Trojan_ShellObject_f4X_aqH1LVc_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f4X@aqH1LVc_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17272438ccd4b2a38f53280ec3960c31cd7b26d7b390d7d4b370302e618a8318"

  strings:
    $s1 = "Dmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}