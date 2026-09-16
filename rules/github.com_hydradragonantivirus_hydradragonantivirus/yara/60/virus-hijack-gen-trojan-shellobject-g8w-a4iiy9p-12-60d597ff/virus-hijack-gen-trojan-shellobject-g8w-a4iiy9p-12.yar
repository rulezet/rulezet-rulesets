rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e8d41254e2a1a9f66fc16cd136d343282e654dadd891ca90a2a86e82fcacc5d"

  strings:
    $s1 = "XSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}