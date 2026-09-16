rule Virus_Hijack_Gen_Trojan_ShellObject_ezZ_aCEmdoo_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ezZ@aCEmdoo_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac738a28e64fd24a7c3a4bb335fcf5c76b2f6e4683fdb108f7767857a10955af"

  strings:
    $s1 = "Huff co" fullword ascii
    $s2 = "l image base: %X  New" fullword ascii
    $s3 = "nACe[1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}