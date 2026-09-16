rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "147a7401608cf3cc40bb113dbe1088dca203a0b72924f780ca26dfa82ab17eb0"

  strings:
    $s1 = "noUS*t}" fullword ascii
    $s2 = "vERT<PU0" fullword ascii
    $s3 = "X{neTe" fullword ascii
    $s4 = "Pmp&$ coNn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}