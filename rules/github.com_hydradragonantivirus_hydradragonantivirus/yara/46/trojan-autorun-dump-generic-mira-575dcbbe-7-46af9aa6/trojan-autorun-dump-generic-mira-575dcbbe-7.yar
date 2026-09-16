rule Trojan_Autorun_Dump_Generic_Mira_575DCBBE_7 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Mira.575DCBBE_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03d0408724b24008b96c9b9bd2c95ea7064700934c0e9a0b2d72dbd31383ed61"

  strings:
    $s1 = "SPEC]v" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}