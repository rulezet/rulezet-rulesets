rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_36_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_36_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f0060af87d3969185cc923072fcda13a87485fae1ddd59a8877b510e3d0bb67"

  strings:
    $s1 = "Emendator" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}