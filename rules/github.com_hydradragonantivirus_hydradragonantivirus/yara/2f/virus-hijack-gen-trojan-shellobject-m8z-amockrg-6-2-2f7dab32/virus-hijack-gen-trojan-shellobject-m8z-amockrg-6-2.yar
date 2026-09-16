rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c304e0c60b0051c970f618665a358145bbb4ddc368a4af593ab6b7c19711efb"

  strings:
    $s1 = "fRAT>S" fullword ascii
    $s2 = "!pTvector<T> too long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}