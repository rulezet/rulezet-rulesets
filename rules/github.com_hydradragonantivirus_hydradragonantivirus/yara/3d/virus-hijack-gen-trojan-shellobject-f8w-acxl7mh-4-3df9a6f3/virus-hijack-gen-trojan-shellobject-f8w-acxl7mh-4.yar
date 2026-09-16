rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCXl7mh_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b935c15ada84a67038165fa4ab12a7465e22a3a11228b6b1a3cea5142cf5552e"

  strings:
    $s1 = "8/Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}