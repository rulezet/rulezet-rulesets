rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_202394e6610d_512 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash3       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash4       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash5       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash6       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash7       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash8       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash9       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash10      = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash11      = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash12      = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"
    hash13      = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash14      = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash15      = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1  = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Nx\"" ascii
    $s2  = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function" ascii
    $s3  = "return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})()," ascii
    $s4  = " f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br" ascii
    $s5  = "ction f000(){return \"NYh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s6  = "){return \"ZFe\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";}" ascii
    $s7  = "n \"Go\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Go\";})(),(func" ascii
    $s8  = ",(function f000(){return \"TKp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s9  = "0(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Qj\";}" ascii
    $s10 = " f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"UE" ascii
    $s11 = "(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\"" ascii
    $s12 = "unction f000(){return \"MBb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BQb\";})(),(function f000(){re" ascii
    $s13 = "function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s14 = "tion f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Ml\";})(),(function f000(){return " ascii
    $s15 = " \"PTs\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(func" ascii
    $s16 = "on f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii
    $s17 = "ction f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"SEo\";})(),(function f000(){retu" ascii
    $s18 = "{return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})" ascii
    $s19 = " f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"G" ascii
    $s20 = "{return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Br\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}