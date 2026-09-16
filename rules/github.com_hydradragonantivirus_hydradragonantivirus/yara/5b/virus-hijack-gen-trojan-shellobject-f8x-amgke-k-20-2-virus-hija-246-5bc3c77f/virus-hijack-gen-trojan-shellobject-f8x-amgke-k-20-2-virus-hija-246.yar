import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_amgke_k_20_2_Virus_Hija_246 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_20_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_211_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_229_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b00888b91be353d18e18c45d23c3967d666971a1f717bd02a9e9850292d73f39"
    hash2       = "8bdbc65ae0a6aadb8fa7c794cdd132edc212aee7be8629710986e62a5e4c7dfe"
    hash3       = "72ac7be72a7dcd60e450126e0d7417a3216d25cb70e13ca09c9be24130fd84fa"

  strings:
    $s1 = "DW Final (Temporary!)" fullword ascii
    $s2 = "unknown computer name" fullword ascii
    $s3 = "Received response \"%s\" from server." fullword ascii
    $s4 = "Received URL response from server.  Would you like to view in your browser?" fullword ascii
    $s5 = "Received URL response.  Would you like to view in your browser?" fullword ascii
    $s6 = " Offset: %08x" fullword ascii
    $s7 = "Wrote CAB to %s" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c4998075f1324ce0f644f12a548d76b1" and (all of them)
    ) or (all of them)
}