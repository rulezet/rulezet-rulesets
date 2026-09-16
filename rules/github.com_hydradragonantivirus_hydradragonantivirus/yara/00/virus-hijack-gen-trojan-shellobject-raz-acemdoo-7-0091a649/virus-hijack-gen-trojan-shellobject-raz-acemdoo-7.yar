rule Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb0e3adeb666d0f8870e9c363d2906a6517eaf63cf273de9ea0cf04d5e9105bd"

  strings:
    $s1 = "jocK!s" fullword ascii
    $s2 = "&Papa'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}