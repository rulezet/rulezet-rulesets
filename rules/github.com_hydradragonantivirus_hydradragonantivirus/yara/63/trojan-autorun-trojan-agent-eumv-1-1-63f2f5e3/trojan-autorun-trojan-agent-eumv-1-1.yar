rule Trojan_Autorun_Trojan_Agent_EUMV_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Agent.EUMV_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34d66acf806e28879561267dfbdd402a8ede499498323f1aded8e7b13f8a11bd"

  strings:
    $s1 = "QUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}