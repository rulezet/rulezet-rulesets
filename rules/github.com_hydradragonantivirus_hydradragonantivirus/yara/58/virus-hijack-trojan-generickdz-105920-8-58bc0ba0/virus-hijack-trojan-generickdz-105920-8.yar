rule Virus_Hijack_Trojan_GenericKDZ_105920_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105920_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf52903a07005bb28a4917a20b044fcf52b0e6ae690130e32ba6019c84cf277d"

  strings:
    $s1 = ":SaKi<e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}