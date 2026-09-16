rule _20160921_033cb159a63153428b22d38108b692e4_20160921_13a6ecf7a8d1_2606 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160921_bcf3911462135150c96c6b8eccf51628.js, 20160921_c459056d51b1a4ea3176139800021b35.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js, 20160921_cbfbdc544b309301bc71d300d7726545.js, 20160921_d6dc24b88112bfdeca39a6062c7510f7.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash3       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash4       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash5       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash6       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash7       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash8       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash9       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash10      = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash11      = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash12      = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash13      = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash14      = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"
    hash15      = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"
    hash16      = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"
    hash17      = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"
    hash18      = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"
    hash19      = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"
    hash20      = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"
    hash21      = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "{return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oh\";})(" ascii
    $s2 = "ion f000(){return \"Br\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"" ascii
    $s3 = "(){return \"Br\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})" ascii
    $s4 = "unction f000(){return \"Oh\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Rh\";})(),(function f000(){retu" ascii
    $s5 = "function f000(){return \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){re" ascii
    $s6 = "f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GG" ascii
    $s7 = "ion f000(){return \"PTs\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}