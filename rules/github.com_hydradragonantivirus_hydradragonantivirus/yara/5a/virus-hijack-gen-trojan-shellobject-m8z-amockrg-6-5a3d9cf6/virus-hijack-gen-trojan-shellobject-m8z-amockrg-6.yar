rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d01d19dcd3cd78d0ee669d216cf3ca012002133af4840be7924c0abf41374eb"

  strings:
    $s1 = "assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}