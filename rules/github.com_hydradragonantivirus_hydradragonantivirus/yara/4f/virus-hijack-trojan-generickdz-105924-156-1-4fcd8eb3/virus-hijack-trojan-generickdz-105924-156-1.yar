rule Virus_Hijack_Trojan_GenericKDZ_105924_156_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_156_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e383cea5a6cf7c9b07ea6d53ced042af608339fb3621766fc0cf29788c0465bc"

  strings:
    $s1 = "C:\\Users\\Administrator\\documents\\visual studio 2010\\Projects\\WindowsApplication1\\WindowsApplication1\\obj\\x86\\Release" ascii
    $s2 = "C:\\Users\\Administrator\\documents\\visual studio 2010\\Projects\\WindowsApplication1\\WindowsApplication1\\obj\\x86\\Release" ascii
    $s3 = "Trial Expired" fullword wide
    $s4 = "Your license will expire in {0} days" fullword wide
    $s5 = "PAct`-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}