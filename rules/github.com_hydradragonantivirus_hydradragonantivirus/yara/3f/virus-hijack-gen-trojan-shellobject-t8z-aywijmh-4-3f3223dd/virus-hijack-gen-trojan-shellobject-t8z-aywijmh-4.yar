rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ayWIjmh_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ayWIjmh_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57168c4496f68eebe392e901e0a2ac12dbed2d08aedc83b6ef77e9345dcc5bb8"

  strings:
    $s1 = "]\\!Gutt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}