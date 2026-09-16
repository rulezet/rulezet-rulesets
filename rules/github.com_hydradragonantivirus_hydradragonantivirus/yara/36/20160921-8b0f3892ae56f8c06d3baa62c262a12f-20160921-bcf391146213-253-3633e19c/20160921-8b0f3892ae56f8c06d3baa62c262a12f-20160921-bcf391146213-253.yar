rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160921_bcf391146213_253 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_bcf3911462135150c96c6b8eccf51628.js, 20160921_c459056d51b1a4ea3176139800021b35.js, 20160921_cbfbdc544b309301bc71d300d7726545.js, 20160921_d6dc24b88112bfdeca39a6062c7510f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"
    hash3       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"
    hash4       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"
    hash5       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"

  strings:
    $s1  = "rn \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s2  = "return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})()" ascii
    $s3  = "eturn \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"MBb\";})()" ascii
    $s4  = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Uo\";})()," ascii
    $s5  = "n f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"" ascii
    $s6  = "(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"ZFe\";}" ascii
    $s7  = "rn \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(fu" ascii
    $s8  = "(){return \"Br\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"MBb\";}" ascii
    $s9  = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Yz\"" ascii
    $s10 = "){return \"Nx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s11 = "YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(functi" ascii
    $s12 = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){retur" ascii
    $s13 = "nction f000(){return \"Go\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Br\";})(),(function f000(){retur" ascii
    $s14 = "turn \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s15 = "function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){ret" ascii
    $s16 = "(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"NBs\";}" ascii
    $s17 = ",(function f000(){return \"Vu\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"DYx\";})(),(function f000(){r" ascii
    $s18 = "Nv\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s19 = "j\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s20 = "),(function f000(){return \"Nx\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Br\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}