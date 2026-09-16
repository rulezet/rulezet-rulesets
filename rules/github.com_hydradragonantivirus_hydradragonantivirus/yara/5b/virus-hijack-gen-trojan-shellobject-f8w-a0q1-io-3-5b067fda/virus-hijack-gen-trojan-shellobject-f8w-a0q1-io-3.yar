rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a0q1_io_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a0q1@io_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc73541ff531e3d9ea8faa9555e7b027555e613f94a062106c545c47d4a56a0e"

  strings:
    $s1 = "}or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}