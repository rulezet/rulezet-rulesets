rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aS0V58e {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aS0V58e.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3782439dba06c38428fff37cfb9ed616781c5f433eeb26792343ce576720d7b"

  strings:
    $s1 = "9`loLl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}