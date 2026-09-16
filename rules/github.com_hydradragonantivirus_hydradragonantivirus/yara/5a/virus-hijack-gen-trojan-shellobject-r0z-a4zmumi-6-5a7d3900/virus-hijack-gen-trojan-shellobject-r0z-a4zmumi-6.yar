rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_a4Zmumi_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@a4Zmumi_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cdb935af7934bc593916dbc0ea7679e159313ac591513de3c529641a0436a36"

  strings:
    $s1 = ":rEPS@8u" fullword ascii
    $s2 = "auBE`V " fullword ascii
    $s3 = "BiKH<X" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}