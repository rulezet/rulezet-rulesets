rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_0550bef558fb_408 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js, 20160921_e432cba10cde369693d6b125dda112c7.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js, 20160921_f1cc02f488792b7161849f8d15549315.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_37d3775ea966a92be28550dbc5135955.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash3       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash4       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash5       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash6       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash7       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash8       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash9       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash10      = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash11      = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash12      = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash13      = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"
    hash14      = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"
    hash15      = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash16      = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"
    hash17      = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"
    hash18      = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"
    hash19      = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"
    hash20      = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash21      = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"
    hash22      = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash23      = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"
    hash24      = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1  = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"RLk\";}" ascii
    $s2  = " f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GG" ascii
    $s3  = "{return \"TKp\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})" ascii
    $s4  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KDh\";})(),(function f000(){retur" ascii
    $s5  = "turn \"Nv\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s6  = ";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f" ascii
    $s7  = ",(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){" ascii
    $s8  = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"DNa" ascii
    $s9  = "return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})()" ascii
    $s10 = "})(),(function f000(){return \"Uo\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s11 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii
    $s12 = "\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Oe\";})(),(function f" ascii
    $s13 = "tion f000(){return \"Br\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return" ascii
    $s14 = "nction f000(){return \"ZFe\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"UEg\";})(),(function f000(){ret" ascii
    $s15 = "(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s16 = "n\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f" ascii
    $s17 = "00(){return \"KDh\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s18 = "000(){return \"Go\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s19 = "n f000(){return \"NYh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"G" ascii
    $s20 = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Um\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}