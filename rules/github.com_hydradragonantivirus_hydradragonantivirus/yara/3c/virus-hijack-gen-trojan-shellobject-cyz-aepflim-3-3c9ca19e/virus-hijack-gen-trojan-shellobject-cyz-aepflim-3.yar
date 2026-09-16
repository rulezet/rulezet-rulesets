rule Virus_Hijack_Gen_Trojan_ShellObject_CyZ_aepfLIm_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CyZ@aepfLIm_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49b44c3e308674f4ac82b812ad1a02ed6fa37a8092f02e84566756c2f5a07b46"

  strings:
    $s1 = "(NASi'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}