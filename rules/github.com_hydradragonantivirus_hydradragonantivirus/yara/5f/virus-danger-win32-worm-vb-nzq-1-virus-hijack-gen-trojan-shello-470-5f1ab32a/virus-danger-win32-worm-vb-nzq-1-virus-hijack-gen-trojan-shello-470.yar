rule _Virus_Danger_Win32_Worm_VB_NZQ_1_Virus_Hijack_Gen_Trojan_ShellO_470 {
  meta:
    description = "datamaliciousorder - from files Virus.Danger_Win32.Worm.VB.NZQ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_5_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_200_1.vir, Virus.Sysbot_Dropped.Generic.AutorunINF.Recex.1.1C7C33CC.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"
    hash2       = "0f2abb00c3b99fca9398ac1b5865eeca43473df46a831adad1c18205865005e0"
    hash3       = "e017175bbb5b8bf16f81791bbf9e401d9c4a0fa91df6f2b0e2a8efb20546fd75"
    hash4       = "07a4111d358e8cddb418a922731ac19176f72aeb437b9f71de41fa73b61a9d7f"
    hash5       = "766efc1c6387b1f63c6b26c153e828d991f36f13c8f5ba951abfc7d78fb881d5"
    hash6       = "35d8375f875d52e88ee0e1805608fd521d1a4e610cd4e4d65576effd60dc2e8d"
    hash7       = "6607cf792b083f99fa7addb8d9c6c261cf597297b4d3be2d99429de6d4d956d5"

  strings:
    $s1  = "runtime from http://www.adobe.com/go/getair, then launch" fullword wide
    $s2  = "from http://www.adobe.com/go/getair." fullword wide
    $s3  = "Please download the latest version of the" fullword wide
    $s4  = "You can download the latest version of the runtime" fullword wide
    $s5  = "author for an updated version." fullword wide
    $s6  = "Adobe AIR which is no longer supported." fullword wide
    $s7  = "Adobe AIR could not be found." fullword wide
    $s8  = "Use \"-runtime <dir>\" to specify the location of the runtime." fullword wide
    $s9  = "This application requires a version of" fullword wide
    $s10 = "Please contact the application" fullword wide
    $s11 = "This application requires Adobe AIR to function." fullword wide
    $s12 = "the application again." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}