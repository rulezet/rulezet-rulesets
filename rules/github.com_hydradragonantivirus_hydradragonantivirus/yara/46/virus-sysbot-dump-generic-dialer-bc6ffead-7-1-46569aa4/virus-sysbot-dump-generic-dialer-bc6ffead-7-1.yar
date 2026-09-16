rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d53aab2d7d813203a5ca1b38577ac87320c5982688171e70359b9f718186cfd8"

  strings:
    $s1 = "{BEld%n(" fullword ascii
    $s2 = "laSk) t64K" fullword ascii
    $s3 = "w$Sier]C[" fullword ascii
    $s4 = "ganT)L" fullword ascii
    $s5 = "StOP)g" fullword ascii
    $s6 = ";TIdY " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}