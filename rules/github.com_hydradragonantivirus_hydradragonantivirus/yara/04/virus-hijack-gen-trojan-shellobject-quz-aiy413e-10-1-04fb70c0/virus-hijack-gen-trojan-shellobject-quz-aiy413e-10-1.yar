rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf05a1fdd420d996b3916755575543a0672d2eeb92573eaf5c548c616693407d"

  strings:
    $s1 = ">heMl#T" fullword ascii
    $s2 = "SIMIty" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}