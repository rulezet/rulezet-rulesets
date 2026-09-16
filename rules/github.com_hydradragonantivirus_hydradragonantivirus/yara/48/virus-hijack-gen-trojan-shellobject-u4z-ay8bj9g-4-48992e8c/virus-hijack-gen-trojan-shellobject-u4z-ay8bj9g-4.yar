rule Virus_Hijack_Gen_Trojan_ShellObject_u4Z_ay8bj9g_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u4Z@ay8bj9g_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bec6d89e03c97dca3ecb6d0c1adde61843809c2df1788cbd03ed98a40aa171c8"

  strings:
    $s1 = "Lmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}