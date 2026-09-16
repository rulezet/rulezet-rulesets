rule Virus_Hijack_Gen_Trojan_ShellObject_h8Z_aKTibuk_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8Z@aKTibuk_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9417f8e2ba9a8cedf58f63a7407fbab7f2f8e8d34a899f8d85a75fd020ae3014"

  strings:
    $s1 = "Rich!l" fullword ascii
    $s2 = ":LyNX)Y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}