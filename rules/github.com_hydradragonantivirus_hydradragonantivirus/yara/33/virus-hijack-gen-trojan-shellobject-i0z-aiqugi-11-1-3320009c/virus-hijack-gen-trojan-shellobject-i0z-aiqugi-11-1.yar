rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "322f321fe5dedd58ed4a688ee86e673380cfefdcca7de4ca1fcd66296ef18534"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><t" ascii
    $s2 = "ttp://schemas.microsoft.com/SMI/2005/WindowsSettings\"><dpiAware>true</dpiAware></asmv3:windowsSettings></asmv3:application><ms_" ascii
    $s3 = "QQScLauncher Version 1.0" fullword wide
    $s4 = "(C) 360.cn All Rights Reserved." fullword wide
    $s5 = "Copyright (C) 1999-2021 Tencent. All Rights Reserved" fullword wide
    $s6 = "'c MaTe&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}