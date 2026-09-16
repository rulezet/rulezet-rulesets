rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_18e4d81197d6_348 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash3       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash4       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash5       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash6       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash7       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash8       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash9       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash10      = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"
    hash11      = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"
    hash12      = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"
    hash13      = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash14      = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"
    hash15      = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"
    hash16      = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash17      = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1  = "rn \"Br\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(func" ascii
    $s2  = "turn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"UEg\";})(),(" ascii
    $s3  = "f000(){return \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"RPt" ascii
    $s4  = " \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s5  = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"UEg\";})(),(" ascii
    $s6  = "r\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function " ascii
    $s7  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return" ascii
    $s8  = "\"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(functi" ascii
    $s9  = "on f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s10 = "00(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Tb\"" ascii
    $s11 = "(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s12 = "n \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(func" ascii
    $s13 = "){return \"Oe\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Br\";})(" ascii
    $s14 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Qa\";})()" ascii
    $s15 = "(){return \"Um\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s16 = "Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function" ascii
    $s17 = "turn \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"RPt\";})(),(" ascii
    $s18 = "unction f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Wy\";})(),(function f000(){retu" ascii
    $s19 = "eturn \"Sj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s20 = "tion f000(){return \"DYx\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}