rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aqOJzSd_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "355e21a2e12e899c341e61e8395f430d80de1d0756de2b427072676b6c184613"

  strings:
    $s1 = "POOh;(A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}