rule _Trojan_Autorun_Trojan_GenericKD_72517131_93_1_Trojan_Autorun_Tr_314 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72517131_93_1.vir, Trojan.Autorun_Trojan.GenericKD.72517131_94_1.vir, Trojan.Autorun_Trojan.GenericKD.73131881_1.vir, Trojan.Autorun_Trojan.GenericKDZ.101457_1_1.vir, Trojan.Autorun_Trojan.GenericKDZ.70387_40_1.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_3_1.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_4_1.vir, Trojan.Autorun_Trojan.GenericKDZ.74320_11_1.vir, Trojan.Autorun_Trojan.GenericKDZ.74320_24_1.vir, Trojan.Autorun_Trojan.GenericKDZ.74320_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.VAZ@aCEmdoo.vir, Virus.Hijack_Gen.Trojan.ShellObject.VAZ@aCEmdoo_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6a357e523ed6bb8fbd373578de488ebe39e700186f4f4ed8a7092be6b13593a"
    hash2       = "8ef9a89c5f5219a2a732b2483a28c96747babffd523606677d61ab74100a74e5"
    hash3       = "dd18c3e61e9b6ecd58a6c4197727ed9fa3520cf7aa34db53cf4bdbacdd3d8858"
    hash4       = "d9313ad170f38982c0b9f8e75017426ffc2b45740fb744cfb94396952f26101e"
    hash5       = "1386910048c41a44e29ad84493e4f8a40668f9557cd3e0bc3cc5c9c5c62cafed"
    hash6       = "86b79554a5c3f55739c93d909308e5cdfafe0883bfe44e2cae35d366f21006c6"
    hash7       = "bd6ef55c97c4e362cb909205f130485768fa8aeb0ef4c8bdb812c4744b15ef1d"
    hash8       = "ceed7c9f8490db970df84194fe478d63ff9f38f4d12a4406d0632422f454fac9"
    hash9       = "80254a576137202e6e81eda3008e2f0d3c5961824ac6e57be969ba6acfdbfa90"
    hash10      = "a3e008cdb7dd18c850033d12497eca06b4d90980899aad9ea2f2622b5b7b28cd"
    hash11      = "e22bfd1e60e6dc5e35d92189bbce53d00dfd63d473c4942dd033a8bdd0e4bd11"
    hash12      = "85ae941f108965fd3b9218f686dd5c71e27a282453c03073e678bd72027b42c9"

  strings:
    $s1 = "Platform.?$WriteOnlyArray@P$AAVTypedTemplate@ViewModel@SystemSettings@@$00" fullword wide
    $s2 = "SystemSettings.ViewModel.?$BindableVector@P$AAVObject@Platform@@" fullword wide
    $s3 = "SystemSettings.ViewModel.?$BindableVector@P$AAVString@Platform@@" fullword wide
    $s4 = "Platform.?$WriteOnlyArray@P$AAVSettingEntry@ViewModel@SystemSettings@@$00" fullword wide
    $s5 = "Platform.?$WriteOnlyArray@P$AAUISettingItem@DataModel@SystemSettings@@$00" fullword wide
    $s6 = "Concurrency.details.?$_AsyncTaskThunk@U?$_AsyncAttributes@V<lambda_93423785fe59be9ae284e4fe6c621267>@@XP$AAVConstraintIndexOptio" wide
    $s7 = "setting: %ws, page: %ws" fullword ascii
    $s8 = "Kthen() cannot be called on a default constructed task." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}