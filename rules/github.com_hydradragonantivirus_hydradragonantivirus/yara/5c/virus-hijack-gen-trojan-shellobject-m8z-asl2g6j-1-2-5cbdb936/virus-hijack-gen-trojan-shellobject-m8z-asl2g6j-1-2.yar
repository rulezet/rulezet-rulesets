rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aSl2g6j_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aSl2g6j_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce8425ade95b675edff08bca0195bb49bea6fc33daa833bcce2c05699c5afcf0"

  strings:
    $s1 = "LLyn&]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}