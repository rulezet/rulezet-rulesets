rule Trojan_Danger_Trojan_GenericKD_72853156_362 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_362.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aada3ac7c110080efaddb69238a5e071df65bebc407112898b8f0de049bf23cd"

  strings:
    $s1 = "....................................................................Acrobat Reader DC.lnk.exe" fullword ascii
    $s2 = "................................................................................................................................" ascii
    $s3 = "................................................................................................................................" ascii
    $s4 = "....................................................................Acrobat Reader DC.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}