rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aqOJzSd_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9942aba11d3ab9e3b2b2f4686d31ddde7b975577d0c63d09473192dbe5b6ff8"

  strings:
    $s1 = "DEMOs  %" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}