rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "408eb1e94afab037dca9a2d0cda6c537f9845abf3b050e4acfa3eeb8b6350f4c"

  strings:
    $s1 = "r}paLY" fullword ascii
    $s2 = "PIeN;d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}