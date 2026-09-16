rule Trojan_Danger_Gen_Trojan_Heur_duZ_HPIO3zfb_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Trojan.Heur.duZ@HPIO3zfb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57ca9140bfc0c0cf0ef888394773ef12caf3c1abb8cd11f98fd40292a19a3c3d"

  strings:
    $s1 = "7_program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "7_program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}