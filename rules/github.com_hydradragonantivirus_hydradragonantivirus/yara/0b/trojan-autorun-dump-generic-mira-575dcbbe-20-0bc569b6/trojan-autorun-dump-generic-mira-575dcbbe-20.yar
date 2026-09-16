rule Trojan_Autorun_Dump_Generic_Mira_575DCBBE_20 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Mira.575DCBBE_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d658e1e0b952f91cfb02277395ec87cd4dd936c8a5753fccfc0fe7b3eec5452"

  strings:
    $s1 = "=software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}