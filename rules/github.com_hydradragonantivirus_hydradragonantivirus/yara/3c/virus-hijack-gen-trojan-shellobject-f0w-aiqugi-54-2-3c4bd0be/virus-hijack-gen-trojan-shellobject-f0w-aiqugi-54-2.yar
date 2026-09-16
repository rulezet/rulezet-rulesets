rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_54_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_54_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5c8eb6c897258f7ba995c557ca172ae7850225f5e39b94c58024a278b52951c"

  strings:
    $s1 = "?$SifT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}