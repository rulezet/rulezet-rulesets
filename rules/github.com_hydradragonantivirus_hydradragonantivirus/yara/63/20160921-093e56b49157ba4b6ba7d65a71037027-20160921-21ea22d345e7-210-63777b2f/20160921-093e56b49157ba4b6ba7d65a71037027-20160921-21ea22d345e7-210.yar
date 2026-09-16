rule _20160921_093e56b49157ba4b6ba7d65a71037027_20160921_21ea22d345e7_210 {
  meta:
    description = "datamaliciousorder - from files 20160921_093e56b49157ba4b6ba7d65a71037027.js, 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_247788e339dc74bbc88f76ce47a9ad41.js, 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js, 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_920f820521e7af7d81b11e9545080390.js, 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_9addbf25729a1d4b42c35fbdfee2e294.js, 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_b9d88469e8af8cdd67a843044d05e2bd.js, 20160921_c0cd20cf50e8d47fdd1303227435227a.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js, 20160921_d881ddcdbb8b37adbff592aab3771b78.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668a3627d0c7aef7745fe8887088d7f4ec88fb6a39c2470772085711e7db7c98"
    hash2       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash3       = "8d162c56b101895f4375e57c40971578d34e8dd1fdd076db93d245dcdade7a48"
    hash4       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash5       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash6       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash7       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"
    hash8       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash9       = "c4a6a94fe43f214f35574405d899a6d61259c2b1135c1ecf399630de11c6dea3"
    hash10      = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash11      = "ec349891ac6c40b31c9f4aa62af04d8c399b64bf3db62ab4c615e3eb0931f1e6"
    hash12      = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash13      = "691dd89731d938aee086465dd311d329fb4ba2f7cee53317fdbdb84c69d5bea1"
    hash14      = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"
    hash15      = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"
    hash16      = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"
    hash17      = "008cc7d5c2f70bbd365de36ecf9be04883f520550cbb34940b2aaf96e55207e3"
    hash18      = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"
    hash19      = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"
    hash20      = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1  = "unction fuck(){return \"GJx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){ret" ascii
    $s2  = "eturn \"Jg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s3  = "fuck(){return \"Xw\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\"" ascii
    $s4  = "ction fuck(){return \"PDf\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){retu" ascii
    $s5  = "Xf\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s6  = "{return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s7  = "nction fuck(){return \"Jo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s8  = "n \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"YAv\";})(),(f" ascii
    $s9  = "fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MB" ascii
    $s10 = "{return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s11 = " \"Cd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"LGo\";})(),(func" ascii
    $s12 = "(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"YAv\";})(),(function fuck(" ascii
    $s13 = "ck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\"" ascii
    $s14 = "unction fuck(){return \"Oh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s15 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jh\";})(),(funct" ascii
    $s16 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Vf\";})(),(fun" ascii
    $s17 = "fuck(){return \"Jg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MB" ascii
    $s18 = " fuck(){return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"J" ascii
    $s19 = "uck(){return \"GWo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MB" ascii
    $s20 = ")(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}