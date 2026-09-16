import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_2_2_Virus_Hijac_363 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_5_2.vir, Virus.Sysbot_Dropped.Generic.AutorunINF.Recex.1.1C7C33CC.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f2abb00c3b99fca9398ac1b5865eeca43473df46a831adad1c18205865005e0"
    hash2       = "e017175bbb5b8bf16f81791bbf9e401d9c4a0fa91df6f2b0e2a8efb20546fd75"
    hash3       = "07a4111d358e8cddb418a922731ac19176f72aeb437b9f71de41fa73b61a9d7f"
    hash4       = "766efc1c6387b1f63c6b26c153e828d991f36f13c8f5ba951abfc7d78fb881d5"
    hash5       = "6607cf792b083f99fa7addb8d9c6c261cf597297b4d3be2d99429de6d4d956d5"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<script type=\"text/javascript\" src=\"https://coinhive.com/lib/coinhive.min.js\"></script>" fullword ascii
    $s3 = ",Qihoo 360 Software (Beijing) Company Limited1" fullword ascii
    $s4 = ",Qihoo 360 Software (Beijing) Company Limited0" fullword ascii
    $s5 = "var miner = new CoinHive.Anonymous('yuNWeGn9GWL72dONBX9WNEj1aVHxg49E');" fullword ascii
    $s6 = "(C)360.cn All Rights Reserved." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "53d02dee8a3558f2a2295b34eb0d6374" and (1 of ($x*) and all of them)
    ) or (all of them)
}