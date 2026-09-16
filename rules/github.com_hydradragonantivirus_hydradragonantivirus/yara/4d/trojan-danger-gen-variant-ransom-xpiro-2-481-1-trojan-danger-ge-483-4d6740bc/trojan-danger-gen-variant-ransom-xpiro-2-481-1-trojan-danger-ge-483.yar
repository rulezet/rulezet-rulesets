import "pe"
rule _Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_481_1_Trojan_Danger_Ge_483 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_481_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_118_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_121_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_137_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_139_1.vir, Trojan.Danger_Generic.Dacic.1A7FA519.A.24019597_1.vir, Trojan.Danger_Generic.Dacic.1A7FA519.A.2A6245F4_1.vir, Trojan.Danger_Generic.Dacic.1A7FA519.A.2D3D82A8_2_1.vir, Trojan.Danger_Generic.Dacic.1A7FA519.A.2D3D82A8_4_1.vir, Trojan.Danger_Trojan.GenericKD.35816276_1_1.vir, Trojan.Danger_Trojan.GenericKD.44959075_1_1.vir, Trojan.Danger_Trojan.GenericKD.67064203_16_1.vir, Trojan.Danger_Trojan.GenericKD.67064203_17_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_169_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_177_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_253_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_318_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_376_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_423_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_57_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_73_1.vir, Trojan.Danger_Trojan.GenericKD.67269844_2_1.vir, Trojan.Danger_Trojan.GenericKD.72304918_152_1.vir, Trojan.Danger_Trojan.GenericKD.72304918_203_1.vir, Trojan.Danger_Trojan.GenericKD.72304918_5_1.vir, Trojan.Danger_Trojan.GenericKD.72304918_77_1.vir, Virus.Danger_Gen.Trojan.ShellObject.i8Y@a4YD!Xe.vir, Virus.Danger_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_1.vir, Virus.Danger_Gen.Trojan.ShellObject.k8Z@a4YD!Xe.vir, Virus.Danger_Gen.Trojan.ShellObject.k8Z@aqgEuSk.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_10.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_11.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_12.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_13.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_14.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_15.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_16.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_7.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_9.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@ayu38pk.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@ayu38pk_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@ayu38pk_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@ayu38pk_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@ayu38pk_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@ayu38pk_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aC9JiEk.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aC9JiEk_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_5.vir, Virus.Hijack_Trojan.GenericKDZ.103285_21.vir, Virus.Hijack_Trojan.GenericKDZ.103285_235.vir, Virus.Hijack_Trojan.GenericKDZ.103285_251.vir, Virus.Hijack_Trojan.GenericKDZ.103285_263.vir, Virus.Hijack_Trojan.GenericKDZ.103285_319.vir, Virus.Hijack_Trojan.GenericKDZ.103285_341.vir, Virus.Hijack_Trojan.GenericKDZ.103285_349.vir, Virus.Hijack_Trojan.GenericKDZ.103285_37.vir, Virus.Hijack_Trojan.GenericKDZ.103285_386.vir, Virus.Hijack_Trojan.GenericKDZ.103285_475.vir, Virus.Hijack_Trojan.GenericKDZ.103285_587.vir, Virus.Hijack_Trojan.GenericKDZ.103285_588.vir, Virus.Hijack_Trojan.GenericKDZ.103285_682.vir, Virus.Hijack_Trojan.GenericKDZ.103285_719.vir, Virus.Hijack_Trojan.GenericKDZ.103285_813.vir, Virus.Hijack_Trojan.GenericKDZ.103285_99.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eefc46b806a5ef6cbdf213b6953b242519d3774988555809451dea4011fe9b3"
    hash2       = "697b609230c2ee3e722d14bf0057f6e94bc48c66d3da9f9bc7eb01949d86d0cf"
    hash3       = "c22b6a23521272f74806c4810212dfcdca098bc5f5b3f34fd313cc356d27992b"
    hash4       = "7c4a917d1ef6380721abf8d9ebf474022bf2410b6583b81f2e1d81539d6a50ff"
    hash5       = "a89e0df4c0ac30fa4d3e071a0599c92130ca34aa696b38f35d5d8d1f6530f06c"
    hash6       = "ae14810a243382653251d15618ee77d96be3fef2719d39b18409fe16f3a79fc6"
    hash7       = "2542eee1bc185aef80608c6b9f78de0cff5266d460eea9363958a8dff6c8087e"
    hash8       = "db7bb3d8d2c31b8d2dace9c4bb7e2ab8879c080873159b78087d4bf4f32d4c44"
    hash9       = "aa3d9d6f0827475cb2306d6686dae4db5e2b3489de41d54ef54bf3d88e585978"
    hash10      = "f8d3bfffa74fcb49a5f02e9cd70f1ff90bb0a8110f721cd4d931411f12839f94"
    hash11      = "8901c149b40ff30c7dccdb1eabda34b70553e639f65ce3e50864c725870ad57e"
    hash12      = "6d7fe70449a260bf09358bf9f49e678558b6e67180b38cf316c20e641ba75b1a"
    hash13      = "e58e63788d9d304ca609ec76137db61905ad07be340208d28780d3d0ff8c4094"
    hash14      = "0ea6a6722bc475ca67bf5e3cf4bc996b73ff8ebe57c363a832692159fe1f7adb"
    hash15      = "efb2e14cddcf5a62cb5af246337d0c9e6aa41e6561f2877e5f5e90974b436586"
    hash16      = "ad756faaed649ff9d1eb609f9fcf276e032504b0364b9cf767d1ed2187cf5e80"
    hash17      = "5773fd890e396d564c200a169f57bfaa4b651ce241de23b4a306e1a992ee2d69"
    hash18      = "4e786119ae2a70e8e2a12f276cc1a77ef617238e9a93da1b5904bd8d3f3281f3"
    hash19      = "b0831a7325bd7aa729288172b8c7eb31de803a0d144567ab19eb01913fec7440"
    hash20      = "00de0c8b493956f513c19a8b0bb0d193e5e2eb3d3460ea8f7d1e53c6b1df0c82"
    hash21      = "61771b884ca300730fe0647a46794304177014586497d2185def422b1b0643a2"
    hash22      = "cab6d371626ddafd361f88e1f54c37445f8ae2579033c65c1b9481aa8b5f3ead"
    hash23      = "2bcbf6d3dbc7d40657e39d4c47c432082a5b9a7f6c9bab4a543914775e9a3b7b"
    hash24      = "7731fc0a3255963681b2a5309bd65e58a5ba8bbfbafbfdccfa001534cbac1032"
    hash25      = "b9e0ea59f4e26a11f7e0afd85498ddde1f9adf92a9ab4166f0d3fa470ad5b838"
    hash26      = "2157b588a021d72f450db6d50bf1b5afd91300601f7c2a9a23525011823442a8"
    hash27      = "996c382c8e7f7c1fb1f7ec84dd35b6126ee82f7bd10a823c3540a6d4b5bf758a"
    hash28      = "f95caed3cc90fe74fd6091b1b875ce3ab182c007c68bcb420e3bf412e971d10f"
    hash29      = "35c5cb7879fa199c16be5442861f3cb22067100891643cc4c100358f865dd965"
    hash30      = "69154e7a2b91fd93bc91073bc16b92818454a0f31f0b2f1c7d95516c650d33f8"
    hash31      = "029bba9a2dc3214046b86a67c5a5e6cbf51a1639e13334262a7fd32715cbf89c"
    hash32      = "82bd4678edb0c04b2d8f6aab1127bb25ccfef32830add671a1cc331c50f3b66f"
    hash33      = "970a0fac2a290a0920a18bc03796a34fbb115e4fd9fd5df1f83e1995c1e15ca8"
    hash34      = "47a5cb3c503b964d070e750fab365e609ea1f7b7c5e171711a8720f93f8a8db0"
    hash35      = "0680543fd32a0f1a51fae10f9ba4e24900b3ee80460fe832d1879748d7abc699"
    hash36      = "6f0f224ac8b766b920a1bcdf6c3cbc865f6e3ba8c65673a10bd42a6c6769db04"
    hash37      = "bc3611ec9537bbfa1e87526463c3eda7c45ee9ca332acd2ede608ac15df486bb"
    hash38      = "74840c1b2d146ba8ab8c38db7e049edd3712c46a9bcb727af1c03d81c8c9652e"
    hash39      = "ada73ff203356edeec4e5b5abcbf6bf64c47a29f9c83505d6845718a6acbcc70"
    hash40      = "07569a9ccfb1acc822a32bd9036076f2269ec1d06d0b72cd4975f1c6d44ec94c"
    hash41      = "34ae4c4d05f400f4a79c2af819bce6e7a28cbec5887f0dad59118341429e8075"
    hash42      = "5e7e5318e05a284d7cdb597851ec3736c3f4dbe7c731b39986d4b8e15c72bb25"
    hash43      = "91628104dc8307c7c69498e470fc94225f9f65b1769846ef97e7c17c8f822d84"
    hash44      = "90fa679ae493424ca55785dfaf9a387679bfdb18e9a8824101612be91a197dad"
    hash45      = "5d3bec734e9a701bda39548f119c777641c2c3885a7197c57281e81564e134ee"
    hash46      = "4a8589f163a79182a4e7bc76ee433e0ed8f2834b0c2da5d055f1856190cc6617"
    hash47      = "2d9cf85de50686fa1e5c91cf1ecaa9775d7853cce05ec4ee5bc2b09bdcf9e234"
    hash48      = "07c2b1d7187877197fc139de23d6bd1235a14ace6b10369357f3b28bf422a005"
    hash49      = "0cfc7df2dfe26c7daad18a4d8b5af0e41a098e19b178961720df28a82581d69f"
    hash50      = "d7b2daac422baa745ec6d1ccb9f11657e05ec466cc701526fd63d23ea0ba2d4c"
    hash51      = "57644c0172fbbba2cd2b3aa01b4d92a7e5d2bafaadf995b7602492fb54171bc6"
    hash52      = "af37e221a85f71eba7fd5f5e599a0ed61266c6af1f4f7fbdfff3acf2acad05c2"
    hash53      = "da5724060f77f52a080371123d9eda2d78b28249831b999edfd45c079ea819a4"
    hash54      = "fbb074ac6009b5ea278c5789b8053655097ec03b8ce7382f5ad1fe7bbd698c6a"
    hash55      = "dc8da82fee5dc9e86e46022a053be68f32537e6822e681aa796c49e44b755c19"
    hash56      = "45c388549aa8a66a98ce4eb960a11177b10bcdceda2d1f2d7685c0d2d9cfbdfa"
    hash57      = "f2cc8ac5061f14d6a8538b32ae08cb876b1b2dd9c3dfa60df8fb91a680177645"
    hash58      = "f78233bf39fdc748914dcf3f67b0fd22625db2028ac3fa1ac837d2c85ea8eda0"
    hash59      = "e2a19c776f3f0481c00c9968cc5a48607d0785837f6f6dce89cbaab3ce6b105e"
    hash60      = "a2a3a5a20ed0830f73442e5dd789e743512f346a3ecf7d22cf543da73ec1e4ae"
    hash61      = "536af43cc1f12a08184edafb8171be5b2249be41a3507b39ededdc975665bedc"
    hash62      = "8002e2f22a09b889ab4206a8cc49a45b83bd982d3a7fe8cafec19ce32beda615"
    hash63      = "d852b0ec159608875393d83926f6a530e0d6c2b47ce4a09d6d260b46c69e80b5"
    hash64      = "e483016345a3ca495fab5f6bd7d083d67f9037af7c733d64b0d15d8c5c057946"
    hash65      = "690bd8c0eb420e2a35e57993e0277b1975b27809afe1780a15e12c7db682e69a"
    hash66      = "af8707768e0f1d22a2e0fcb2ca3c1d44d4f56cb3a2b972998599de2d1a74dd31"
    hash67      = "b021309f9f03ed83ff898696ee4fa0e300e5bb409c3d7817bca6c2a107923bd0"
    hash68      = "6a8e9fd5519451c4781fdc9e2dab64f55886a12971284c4eebb8e26d1b820af8"
    hash69      = "bb9cf3479f35d567e8370066b23feb9647f7875c7b1718e92df62ea8457d7f9c"
    hash70      = "aca94ef4bb4f18a812497653fdf187db10bbfb933b9070812ae6dd85f624f459"
    hash71      = "cd628e9ab10894dae07f3704b70090300b4774835fafba4719e4435eb3dcfb45"
    hash72      = "5a1eb7b769d25d02303b502b404defc8cb7ec413cda95037154e0d3dc6a0a9ff"
    hash73      = "4f92fec1ac1f8a09ec5f2921ace039fd9004690bd36628b75c5c61d7b6e534d4"
    hash74      = "65e6fbbc92da4e3507fa492a8a2d322f7682c38fa0dedccd6af708917c837d4a"
    hash75      = "750a4b1d1b6ec0d39b072a8c9fe71b2b0856a5b268004e57831241c6a05d7ea8"
    hash76      = "7f7587b2204573ca5938a1396d8f9394d6caee71cfc207a76b4553b27b6a7c28"
    hash77      = "528ae9ebda8728f836a889a06b1b7c339afeff529914d981bb362b42178858d8"

  strings:
    $s1  = " of Web Conferencing users, a Collaboration Program User within your" fullword ascii
    $s2  = "Professional User 2003: is deor service that is subject to a discount or a promotion when you order the relevant product or serv" ascii
    $s3  = "Professional User 2003: is deor service that is subject to a discount or a promotion when you order the relevant product or serv" ascii
    $s4  = "message dialog.n" fullword ascii
    $s5  = "is the media elements; (ii) grant your custom" fullword ascii
    $s6  = "distributed for limited purposes. You may not se7. Automatic Update. Software with Click-to-Run technology may periodically chec" ascii
    $s7  = "distributed for limited purposes. You may not se7. Automatic Update. Software with Click-to-Run technology may periodically chec" ascii
    $s8  = "distributed for limited purposes. You may not seService, see the Office 2013 Privacy Statement linked at the end of this agreeme" ascii
    $s9  = "Professional User 2003: is de" fullword ascii
    $s10 = "distributed for limited purposes. You may not seService, see the Office 2013 Privacy Statement linked at the end of this agreeme" ascii
    $s11 = "ly be used to acquire products" fullword ascii
    $s12 = " acquire products" fullword ascii
    $s13 = "ice. The list price will be" fullword ascii
    $s14 = "agreement, are the entire agreement for the software and any such supplements" fullword ascii
    $s15 = "k with Microsoft for" fullword ascii
    $s16 = "distributed for limited purposes. You may not se" fullword ascii
    $s17 = "rol of the defense and any settlement negotiations; and" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "0cbc2eff11dfa53aeb939edf8d4efbe8" and (8 of them)
    ) or (all of them)
}