rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_25_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ea7ed16774c3eb8fb1b9dac58b1f37d9c7bf628ef788f2edf54f281a234750f"

  strings:
    $s1 = "-!your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}