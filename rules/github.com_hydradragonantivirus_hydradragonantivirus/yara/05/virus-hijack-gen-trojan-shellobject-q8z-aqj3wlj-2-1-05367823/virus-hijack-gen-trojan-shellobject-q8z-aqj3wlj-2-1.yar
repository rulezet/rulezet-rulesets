rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aqj3wLj_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aqj3wLj_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffb6ef26c5c2b6d5fa1e599c5e2db4104faeb9fdacd337e64fd1a035398f0dc9"

  strings:
    $s1 = "phIZ{M" fullword ascii
    $s2 = "DUSK:q" fullword ascii
    $s3 = "F)BENt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}