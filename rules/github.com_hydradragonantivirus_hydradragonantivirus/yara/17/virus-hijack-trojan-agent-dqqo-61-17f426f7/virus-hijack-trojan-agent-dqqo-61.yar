rule Virus_Hijack_Trojan_Agent_DQQO_61 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_61.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f173eebe784451ab004f794ccd2c53f8ca7b3dc4700cf874b70f86b8b7747910"

  strings:
    $s1 = "'America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}