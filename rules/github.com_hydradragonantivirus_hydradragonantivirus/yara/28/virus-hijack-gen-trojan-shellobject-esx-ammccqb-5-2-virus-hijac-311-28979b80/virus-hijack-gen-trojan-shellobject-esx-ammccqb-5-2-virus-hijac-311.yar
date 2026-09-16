import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_311 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "5847c0d50553d832c289b21658cf64bdae66267b2ef73b3751231791c076e525"
    hash3       = "ba64fce50534b1583891982a16956c9a24ae91daea1668605d102620b6677b2d"
    hash4       = "a51d302b290f4adb2da2151a0e108dc587a629823864d99310dcb2e56fb5feb3"

  strings:
    $x1  = "3,\"System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\",\"C:\\Windows\\assembly\\NativeImages_v4.0.30319" ascii
    $s2  = "3,\"System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\",\"C:\\Windows\\assembly\\NativeImages_v4.0.30319" ascii
    $s3  = "Sig[4].Name=Fault Module Version" fullword wide
    $s4  = "DynamicSig[1].Name=OS Version" fullword wide
    $s5  = "Sig[6].Name=Exception Code" fullword wide
    $s6  = " installer has stopped working" fullword wide
    $s7  = "Sig[3].Name=Fault Module Name" fullword wide
    $s8  = "Sig[5].Name=Fault Module Timestamp" fullword wide
    $s9  = "Sig[7].Name=Exception Offset" fullword wide
    $s10 = "DynamicSig[22].Name=Additional Information 1" fullword wide
    $s11 = "DynamicSig[23].Name=Additional Information 2" fullword wide
    $s12 = "DynamicSig[24].Name=Additional Information 3" fullword wide
    $s13 = "DynamicSig[25].Name=Additional Information 4" fullword wide
    $s14 = "UI[5]=Check online for a solution and close the program" fullword wide
    $s15 = "UI[6]=Check online for a solution later and close the program" fullword wide
    $s16 = "UI[7]=Close the program" fullword wide
    $s17 = "FriendlyEventName=Stopped working" fullword wide
    $s18 = "Sig[1].Name=Application Version" fullword wide
    $s19 = "Sig[0].Name=Application Name" fullword wide
    $s20 = "UI[4]=Windows can check online for a solution to the problem." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}