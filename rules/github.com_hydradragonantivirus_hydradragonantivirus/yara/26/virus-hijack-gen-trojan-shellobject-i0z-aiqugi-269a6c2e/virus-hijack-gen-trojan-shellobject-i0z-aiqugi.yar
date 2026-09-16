rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbf0f067dd2bfd6c51875f7a5126f802a903ca2ffede8d0092b1f74e78ec8385"

  strings:
    $s1 = "Hued]'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}