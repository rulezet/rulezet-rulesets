rule Virus_Hijack_Gen_Trojan_ShellObject_mWZ_aeFgVVo_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mWZ@aeFgVVo_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5d79445cfa6e7991d9a466a0e9d822fe27be596beb1f8ec65f7be60c14e1e40"

  strings:
    $s1 = "Password Protection Service.exe" fullword wide
    $s2 = "Password Protection Service.pdb" fullword ascii
    $s3 = "Password Protection Service.g.resources" fullword ascii
    $s4 = "Password Protection Service" fullword wide
    $s5 = "<script language='javascript'>alert( \"This assembly is protected by an unregistered version of IntelliLock!\" );</script>" fullword wide
    $s6 = "This assembly is protected by an unregistered version of \"IntelliLock\"!" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}