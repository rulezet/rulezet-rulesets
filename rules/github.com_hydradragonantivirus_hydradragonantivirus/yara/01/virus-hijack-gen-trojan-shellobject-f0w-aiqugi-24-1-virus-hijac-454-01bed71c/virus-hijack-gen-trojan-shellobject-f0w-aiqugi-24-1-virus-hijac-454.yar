rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_24_1_Virus_Hijac_454 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_24_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_70_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_6_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_14_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f4X@aqH1LVc_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a0q1@io_7.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14f7822f1705086298a7009d9d07fad693bcb09ffa8f03e92a9f89703bfafdc7"
    hash2       = "fed8ef3de76f9637c2bb13cb3e2380a8a43339fdd22e4ed2f2b2d815f3d1bba9"
    hash3       = "fc535bb5260cc4fc2228a73dfc603e16d912963dcafe5b1f114038d8d3c36a18"
    hash4       = "b7ee4b7b12c6dfc8e90ae251bc9aeb1d20a4fcb0c5da0e879d273933728fce75"
    hash5       = "7100148b0a4fd771e764c6763e33c40621b84d691c9459d10270837261c7f547"
    hash6       = "5d54a571e786e400d1592c5a2907d7fb4e053ebf799242ad4c201571a3ce6979"
    hash7       = "3bdae181df0c1fec2b4d6036483faca4d65bbdbf3e949a63bcebe2423e212cad"
    hash8       = "2d07b9370a598b272df3e34edc27cb1d54d9fa469cae0a3d697642f60f94aa5c"

  strings:
    $x1  = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\drivers\\W32X86\\3\\Old\\1\\FXSTIFF.DLL, |delete operation|" wide
    $x2  = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\drivers\\W32X86\\3\\Old\\1\\FXSUI.DLL, |delete operation|, " wide
    $x3  = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\drivers\\W32X86\\3\\Old\\1\\FXSWZRD.DLL, |delete operation|" wide
    $x4  = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\mxdwdrv.dll, \\??\\D:\\Windows\\sy" wide
    $x5  = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\unidrvui.dll, \\??\\D:\\Windows\\s" wide
    $x6  = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\UNIDRV.DLL, \\??\\D:\\Windows\\sys" wide
    $x7  = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\UNIRES.DLL, \\??\\D:\\Windows\\sys" wide
    $x8  = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\XPSSVCS.DLL, \\??\\D:\\Windows\\sy" wide
    $x9  = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\mxdwdui.dll, \\??\\D:\\Windows\\sy" wide
    $x10 = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\FXSDRV.DLL, \\??\\D:\\Windows\\sys" wide
    $x11 = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\FXSUI.DLL, \\??\\D:\\Windows\\syst" wide
    $x12 = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\FXSWZRD.DLL, \\??\\D:\\Windows\\sy" wide
    $x13 = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\FXSTIFF.DLL, \\??\\D:\\Windows\\sy" wide
    $x14 = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\FXSRES.DLL, \\??\\D:\\Windows\\sys" wide
    $x15 = "11/20/2010 13:48:2 - PFRO Error: \\??\\D:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\FXSAPI.DLL, \\??\\D:\\Windows\\sys" wide
    $x16 = "10/11/2019 6:28:41 - PFRO Error: \\??\\C:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\mxdwdrv.dll, \\??\\C:\\Windows\\sy" wide
    $x17 = "10/11/2019 6:28:41 - PFRO Error: \\??\\C:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\unidrvui.dll, \\??\\C:\\Windows\\s" wide
    $x18 = "10/11/2019 6:28:41 - PFRO Error: \\??\\C:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\unidrv.dll, \\??\\C:\\Windows\\sys" wide
    $x19 = "10/11/2019 6:28:41 - PFRO Error: \\??\\C:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\unires.dll, \\??\\C:\\Windows\\sys" wide
    $x20 = "10/11/2019 6:28:41 - PFRO Error: \\??\\C:\\Windows\\system32\\spool\\DRIVERS\\W32X86\\3\\New\\XpsSvcs.dll, \\??\\C:\\Windows\\sy" wide

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*))
    ) or (all of them)
}