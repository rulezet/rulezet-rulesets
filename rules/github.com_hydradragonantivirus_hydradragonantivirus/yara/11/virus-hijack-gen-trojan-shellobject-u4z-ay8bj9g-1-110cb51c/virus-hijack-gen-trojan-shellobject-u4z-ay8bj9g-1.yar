rule Virus_Hijack_Gen_Trojan_ShellObject_u4Z_ay8bj9g_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u4Z@ay8bj9g_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2db6be3bd387a0a3bc0a7a1f3ec680883e870a69beb169653ed29a59883ab85"

  strings:
    $s1 = "rmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}