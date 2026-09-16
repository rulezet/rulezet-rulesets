rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b124eb4c85af8b4fad0ac56e3498729678992b361322b97f5fce6f372ae718c"

  strings:
    $s1 = "!Error Down" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}