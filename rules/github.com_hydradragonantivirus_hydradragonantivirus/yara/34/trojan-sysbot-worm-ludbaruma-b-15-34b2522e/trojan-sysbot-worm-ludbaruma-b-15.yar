rule Trojan_Sysbot_Worm_Ludbaruma_B_15 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Worm.Ludbaruma.B_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "620c08dab8c751a0febc227d49304c2cebee09c2b8320dd29aff5161c9f496f7"

  strings:
    $s1 = "His program cannot be run in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}