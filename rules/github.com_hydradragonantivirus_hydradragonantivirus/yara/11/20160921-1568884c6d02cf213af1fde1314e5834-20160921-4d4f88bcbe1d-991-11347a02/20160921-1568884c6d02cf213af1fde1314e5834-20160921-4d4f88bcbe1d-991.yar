rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_4d4f88bcbe1d_991 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash3       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash4       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash5       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"
    hash6       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1  = "000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s2  = "c\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYs\";})(),(function" ascii
    $s3  = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Lp\";})(),(function f0" ascii
    $s4  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s5  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tb\";})(),(fu" ascii
    $s6  = "nction f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){retu" ascii
    $s7  = "000(){return \"KDh\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br" ascii
    $s8  = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sq\";})" ascii
    $s9  = "nction f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(function f000(){retur" ascii
    $s10 = "\"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(funct" ascii
    $s11 = "),(function f000(){return \"DAp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000()" ascii
    $s12 = "),(function f000(){return \"DNa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000()" ascii
    $s13 = ",(function f000(){return \"Br\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){r" ascii
    $s14 = " f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Z" ascii
    $s15 = "urn \"Br\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"HJm\";})(),(f" ascii
    $s16 = "turn \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s17 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Go\";})(),(function f000(){return " ascii
    $s18 = "Gq\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s19 = "tion f000(){return \"EZu\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}