import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_21_1_Virus_Hijac_478 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_21_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_35_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_44_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_45_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_54_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_76_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_92_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_95_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_96_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_98_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_14_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_15.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aSlVvue_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "165ab8593c4c6cf2a6647a891f4ab82e68b86d5e5093c2b5d172d2faf1c40a44"
    hash2       = "c6eca640d0e3ff8838cf4c6169c872bf7503ba7bdb29a67200191ee0e3ff3d30"
    hash3       = "2ca996fe55ac5118e03f24c10238caab7f0fde34e216de00ba87c829bf69d9cd"
    hash4       = "75dc85c02f2b8f577496db21c0d128ba742cf456215b56a8d9d51df2c3fc57e1"
    hash5       = "16832fb7af74d4e464fff117b303ccfc4ceb39edb8b2e15075a2c8852b66fdf3"
    hash6       = "d77ebb795b12dfcd287c3d4322608ba6cdc754ce40a1a7109f7c97359a264f44"
    hash7       = "ca3bc292017d7d1c8e8359a3c5aefce6ecf8c61bcb005a803bd51d91ab995d2e"
    hash8       = "0e9aa45b8feef02bdd3b4112befdfce180355bee4e4810aacff018111967ecb1"
    hash9       = "c57fcbdb3b6db5b74932ff6f78f0fae3aa026cab9b525e6618a368099d4fd3d7"
    hash10      = "eb821ec29ac13bf5558e2996a2f6e99d56d48c82037eb97aeefe4f26fd5c0d57"
    hash11      = "c2ca971858018214c3e9822bf32c38d611ed1c82b3e8824ef3c60d14881fa4f9"
    hash12      = "bb627a3228bd7245e6e1b41feba0d80d38f91b3c02d44b8fcab90049ad91c8a5"
    hash13      = "31b05c71e655b4f6f0ab5d6f34defea416ad1e02d511ccddd4b3b55a92816325"
    hash14      = "2d1cfcca3a29257bfdb2b03413289720f013c18031263af607d4d76018e211e1"
    hash15      = "2043615927b919a7acdd249d9cf1287c0858d5bf18a1f2a7e4e93f73220e46e8"
    hash16      = "71a9c5d8b4c4dff0c038ea2b56e07fcf0cf4570bb8df9fc2bdfbff69456fa38a"
    hash17      = "c472c83516b9ca17ebb7c0f72de2f03006cc0a25d7db6acb9b6eaaa1cbfe8b6e"

  strings:
    $x1 = "05/18/21 00:23:22: infinst: Installed file C:\\Windows\\system32\\d3dx10_36.dll" fullword ascii
    $s2 = "/2021 6:36:35 - PFRO Error: \\??\\C:\\Program Files\\Google\\Chro" fullword wide
    $s3 = ":35 - PFRO Error: " fullword wide
    $s4 = "now generated using ETW (Event Tracing for Windows)." fullword ascii
    $s5 = "r, Enter MsDtcAdvancedInstaller::Configure, base\\wcp\\plugins\\msdtc\\msdtcadvancedinstaller-" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a9192bab5c7c795c7488b69a1853f9c2" and (1 of ($x*) and all of them)
    ) or (all of them)
}