rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_ay8bj9g_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@ay8bj9g_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80fdd38e1e596eb483658d363d45b73a263e1ecc052d6e3aaec340c7e4b100b3"

  strings:
    $s1 = "DOOb)84" fullword ascii
    $s2 = "fLIp [^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}