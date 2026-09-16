rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0446efa80ea972b57decec0513dc52e1ee00daf9f6bd0400e0b0b866204575a0"

  strings:
    $s1 = ",shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}