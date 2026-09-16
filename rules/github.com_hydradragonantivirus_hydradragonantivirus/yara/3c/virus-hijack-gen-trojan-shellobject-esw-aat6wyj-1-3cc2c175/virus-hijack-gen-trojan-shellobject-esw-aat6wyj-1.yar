rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_aaT6Wyj_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@aaT6Wyj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d7adbd58e4149399570c94ee05c604af5b47c7035d0d7d27974e9a95c3ec8aa"

  strings:
    $s1 = "KVwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}