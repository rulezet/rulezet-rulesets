rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e03305b47d47c2c1a9d3cd522b99fddd935f9017ada0eb65956fe00dc71c56b3"

  strings:
    $s1 = "ping 127.0.0.1 -n 3" fullword wide
    $s2 = "\" goto loop" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}