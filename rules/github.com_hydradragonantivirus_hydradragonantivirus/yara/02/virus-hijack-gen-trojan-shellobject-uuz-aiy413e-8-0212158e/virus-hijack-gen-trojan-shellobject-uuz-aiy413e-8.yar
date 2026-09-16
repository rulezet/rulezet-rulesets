rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_aiy413e_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@aiy413e_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c9dd8ea437dc21fa6d396bc178cb009c78c937662deda5bbd7b4871accebdfa"

  strings:
    $s1 = ",Reference Viewing Con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}