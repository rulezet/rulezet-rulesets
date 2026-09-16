rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "052cd23a88b7ad6792752638666c89224d42bbb5fd69854e54e3f5206a105f65"

  strings:
    $s1 = "wEassets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}