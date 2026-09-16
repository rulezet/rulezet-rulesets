rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_aKzulAn_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@aKzulAn_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f24065026f39178f40f1ab04e9cd94e5f85c39879b20e0b873575276046cf5f0"

  strings:
    $s1 = "!Gill`" fullword ascii
    $s2 = "{HEAp<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}