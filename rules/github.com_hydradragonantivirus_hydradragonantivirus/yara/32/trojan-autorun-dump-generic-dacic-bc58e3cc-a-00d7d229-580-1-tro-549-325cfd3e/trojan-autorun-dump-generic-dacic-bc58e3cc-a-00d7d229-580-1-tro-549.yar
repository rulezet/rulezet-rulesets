import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_580_1_Tro_549 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_580_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_671_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_679_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_827_1.vir, Trojan.Autorun_Dump.Generic.Mira.575DCBBE_12_1.vir, Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_20_1.vir, Virus.Hijack_Backdoor.Hangup.B_103.vir, Virus.Hijack_Backdoor.Hangup.B_107.vir, Virus.Hijack_Backdoor.Hangup.B_156.vir, Virus.Hijack_Backdoor.Hangup.B_186.vir, Virus.Hijack_Backdoor.Hangup.B_265.vir, Virus.Hijack_Backdoor.Hangup.B_277.vir, Virus.Hijack_Backdoor.Hangup.B_286.vir, Virus.Hijack_Backdoor.Hangup.B_305.vir, Virus.Hijack_Backdoor.Hangup.B_45.vir, Virus.Hijack_Backdoor.Hangup.B_88.vir, Virus.Hijack_Backdoor.Hangup.B_90.vir, Virus.Hijack_Backdoor.Hangup.B_95.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_106.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_221.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_330.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0fbd3c3e46ddc3d7618627444f579ecad7518563ddbe288fa2cb84a52286f27"
    hash2       = "73b17c4d4e8b4ee27a2ba4481d7fb204a65327782c5232aa31a2f81ba12cdee1"
    hash3       = "d3794b3d79dee08ec875d0c270495a7e480221439b8e8779ab74c83f89d31b05"
    hash4       = "514dd2301c5c13c67bb00f1edd2bd9c13b5a6390918e608d317245fd99393424"
    hash5       = "923b8e939c631062481d1c3e3f4a00aaf41513661259640e7f0a917ed42094aa"
    hash6       = "17ef9e191a5e55e594195cd3d285f9af5d4226b5025be17cc647a01ff14dbe6d"
    hash7       = "7b613c0ab6aab9059de5169a8dd9a9c6c00931507f406e2187e96a957f2bf981"
    hash8       = "5c1da469ac33cf243d2ebdd77ac589b3ffe35c965412b37598f70feac5270577"
    hash9       = "a83db12fda105da8c8ba9da614ef022ea4084a3d36f5e1bba0386f74206e2dfd"
    hash10      = "880a2b4d15f937701fe6119512c3e3db1975feccf54fae3156c96b1d8856c5bc"
    hash11      = "6e9ddeff44c1cd73e1f6b73f3a9d9f169b95e232524e46efded3c385a8957eab"
    hash12      = "53efb7c511caeec1683d5a7eaa8d721f832cafa757c7dfb68654ff59dfd2a0f8"
    hash13      = "68a76e0738807e69eb426848f3cf73717e8a1dd82f4fce047ca9bc9193e45dd8"
    hash14      = "ea4207289ae5681fd4379d2f876c65a7fdbd441340f83bec8265eaeea5bd4854"
    hash15      = "6501ff4bfc0b3c5d89fcf05a99af83452c151903848bc7fc7afbd4b4775bc921"
    hash16      = "48899c836822951895d7f0c4eeee7324ce6318eaccef8cec5c24e60849db6b43"
    hash17      = "e5a68262393877ef05495c9a84bb6242dc8655e3e1f27ab49c10ccd20194ef13"
    hash18      = "fe1e07b6d2f4037b0d9f8222964253e09d248c90f8607ca7a3cc9de8709009ef"
    hash19      = "40a41a03e798e6796057a0e8943af218cde29a7d93196dc78ecdfb65f8ece2ad"
    hash20      = "23576c441a4639bc8e061b3a6792cd438e7f878c7635ce095104c585985f8fe2"
    hash21      = "15cef5f75bafea3a500a2833848018140f553602266927afe04bea6fee0de7d4"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup copy of the soft" fullword ascii
    $s2 = "about CEIP, see microsoft.com/products/ceip/EN-US/privacypolicy.mspx.t" fullword ascii
    $s3 = "Software Updates or Product Support acquired" fullword ascii
    $s4 = "or service that is subject to a discount or a promotion when you order the relevant product or service. The list price will be(" fullword ascii
    $s5 = "Mconditions. Microsoft warrants that properly licensed software will perform substantially as described in" fullword ascii
    $s6 = "own most important confidential information or a reasonable degree of care, whichever is greater; (b) to maintain agreements2" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "8aa5c8ecb5ea19e8886dfb9dd9420e22" and (all of them)
    ) or (all of them)
}