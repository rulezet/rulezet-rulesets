rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_18e4d81197d6_396 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash3       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash4       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash5       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash6       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash7       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash8       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash9       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash10      = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash11      = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash12      = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash13      = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash14      = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash15      = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash16      = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"
    hash17      = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"
    hash18      = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"
    hash19      = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"
    hash20      = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash21      = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"
    hash22      = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"
    hash23      = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash24      = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1  = "f000(){return \"Sq\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MJq" ascii
    $s2  = "eturn \"ZGq\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"PTs\";})()," ascii
    $s3  = "ion f000(){return \"YTp\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s4  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"IPu\";})(),(fu" ascii
    $s5  = "tion f000(){return \"ZIi\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"SGs\";})(),(function f000(){retur" ascii
    $s6  = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Uo\";})(),(function" ascii
    $s7  = "(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s8  = "rn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"ZFe\";})(),(f" ascii
    $s9  = "),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Oh\";})(),(function f000()" ascii
    $s10 = "function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"KDh\";})(),(function f000(){r" ascii
    $s11 = "n \"Uo\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s12 = "f000(){return \"YTp\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br" ascii
    $s13 = "000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\"" ascii
    $s14 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Um\";})(),(function f000(" ascii
    $s15 = "on f000(){return \"DYx\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s16 = "return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Km\";})()" ascii
    $s17 = " f000(){return \"IPu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Br" ascii
    $s18 = ";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Um\";})(),(function f000" ascii
    $s19 = "f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy" ascii
    $s20 = "ction f000(){return \"Lp\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}