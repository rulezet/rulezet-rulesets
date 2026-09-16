rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a0q1_io_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a0q1@io_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78fb23d1883ffe97860243902e8a4b49ee876183809b0d08f007cf8d6eecc94f"

  strings:
    $s1 = "%or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}