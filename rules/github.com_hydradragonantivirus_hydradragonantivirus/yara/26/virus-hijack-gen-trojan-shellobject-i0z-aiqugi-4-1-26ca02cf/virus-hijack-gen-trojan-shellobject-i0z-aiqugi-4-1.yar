rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a04a76ada60a943837ab623b8b8104985a10609f5fa8c575cdb235a0b7710e5"

  strings:
    $s1 = "pank(Z3" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}