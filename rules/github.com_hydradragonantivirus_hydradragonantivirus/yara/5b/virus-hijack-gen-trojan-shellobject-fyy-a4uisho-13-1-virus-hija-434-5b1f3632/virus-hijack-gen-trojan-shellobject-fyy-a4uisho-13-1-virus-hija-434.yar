rule _Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_13_1_Virus_Hija_434 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a6ac2dc9a2cda075961a583da5927bd37ded0be847aacb565ec2b368908ffd4"
    hash2       = "6fec340df8dab1022498e4fbdb548471f359c56e2a1f10e98b068f43c0dc5ce2"

  strings:
    $s1 = "Clear Read-Only Flag" fullword wide
    $s2 = "Full File Path to Clipboard" fullword wide
    $s3 = "Close All to the Ri" fullword wide
    $s4 = "Clone to other View" fullword wide
    $s5 = "Move to other view" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}