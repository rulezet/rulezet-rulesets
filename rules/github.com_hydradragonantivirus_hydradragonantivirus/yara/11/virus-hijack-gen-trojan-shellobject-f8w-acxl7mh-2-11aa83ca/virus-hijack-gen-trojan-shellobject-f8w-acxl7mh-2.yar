rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCXl7mh_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f81fa6c837e5877bec750b7a233a8b1b8588fabfe1c0502b2671cc6d38a78ab"

  strings:
    $s1 = "W^Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}