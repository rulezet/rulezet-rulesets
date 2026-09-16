rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_a4IIY9p_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@a4IIY9p_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f8e6afc0846c45861d1c834d7e381160887e882ce21eb18b853ad1d34367c6b"

  strings:
    $s1 = "XSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}