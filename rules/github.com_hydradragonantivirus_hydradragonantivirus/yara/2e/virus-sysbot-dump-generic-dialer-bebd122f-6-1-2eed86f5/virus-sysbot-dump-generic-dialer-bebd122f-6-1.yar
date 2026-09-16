rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "605ae9a671edaaf7ed72ab256213fa384ad3b9d6be7746eb2f23c650401b29d5"

  strings:
    $s1 = "Aiel#R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}