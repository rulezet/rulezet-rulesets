rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_2316e7089bcf_471 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash3       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash4       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash5       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"
    hash6       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash7       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"
    hash8       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"
    hash9       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash10      = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1  = "eturn \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2  = "rn \"MMz\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s3  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return" ascii
    $s4  = " \"Oh\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(funct" ascii
    $s5  = ")(),(function f000(){return \"Oe\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(" ascii
    $s6  = "ction f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f000(){retur" ascii
    $s7  = "})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f0" ascii
    $s8  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){retur" ascii
    $s9  = "\"Br\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"HJm\";})(),(funct" ascii
    $s10 = "on f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s11 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"ZIi\";})(),(function f00" ascii
    $s12 = "unction f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){ret" ascii
    $s13 = "{return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mc\";})" ascii
    $s14 = "turn \"NBs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s15 = ")(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"SGs\";})(),(function f000" ascii
    $s16 = "function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){ret" ascii
    $s17 = " f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KX" ascii
    $s18 = "n f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return " ascii
    $s19 = "eturn \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Wb\";})(),(" ascii
    $s20 = ")(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}