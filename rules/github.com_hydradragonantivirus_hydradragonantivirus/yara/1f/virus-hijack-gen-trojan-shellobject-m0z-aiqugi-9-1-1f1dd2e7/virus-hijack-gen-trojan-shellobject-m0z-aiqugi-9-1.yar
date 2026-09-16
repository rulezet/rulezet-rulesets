rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0e8f5ad52fd1e65519a872ec64b10b3e771e37b38ea9f154df0d4b62acee5e6"

  strings:
    $s1 = "Bush`dL?" fullword ascii
    $s2 = "(:yUCK" fullword ascii
    $s3 = "[7$AMIn" fullword ascii
    $s4 = "d_@kNur" fullword ascii
    $s5 = "$%sKil" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}