rule Virus_Hijack_Trojan_GenericKDZ_98388_70_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_70_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb7c8ed2e6344b403a5c57d68eeec2294b36e13c02b0457423c83c4adb1d7375"

  strings:
    $s1 = "UU@thoN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}