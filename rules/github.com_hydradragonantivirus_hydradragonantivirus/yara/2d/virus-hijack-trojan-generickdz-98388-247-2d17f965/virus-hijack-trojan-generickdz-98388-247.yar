rule Virus_Hijack_Trojan_GenericKDZ_98388_247 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_247.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90625fcca7a587c996920320f010ca579bc3a02555fa3f3b0fddc3f723707bfb"

  strings:
    $s1 = "this agreement, as well as all sums remaining unpaid for programs ordered and/or services received under this agreeme`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}