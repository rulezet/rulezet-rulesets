rule Virus_Hijack_Gen_Trojan_ShellObject_u4Z_ay8bj9g_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u4Z@ay8bj9g_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf95ce80c9b01b017d7230ab3c38c6c29d8448459fa08fb32a6473b097fae6b2"

  strings:
    $s1 = "Internal Compiler Bug: No runtime type matcher." fullword ascii
    $s2 = "(c) 2005-2024 Unity Technologies. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}