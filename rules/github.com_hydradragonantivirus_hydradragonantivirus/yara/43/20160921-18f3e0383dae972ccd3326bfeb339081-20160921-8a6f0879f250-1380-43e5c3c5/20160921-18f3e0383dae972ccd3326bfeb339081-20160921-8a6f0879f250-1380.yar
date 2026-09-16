rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_8a6f0879f250_1380 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash3       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash4       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1  = "on f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s2  = "function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){r" ascii
    $s3  = "00(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";" ascii
    $s4  = "rn \"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(f" ascii
    $s5  = "000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GG" ascii
    $s6  = " \"Sj\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s7  = "(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RLk\";" ascii
    $s8  = " f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw" ascii
    $s9  = "(),(function f000(){return \"Lo\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(" ascii
    $s10 = "q\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s11 = "return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Kw\";})()," ascii
    $s12 = "(),(function f000(){return \"Go\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TKl\";})(),(function f000()" ascii
    $s13 = "function f000(){return \"Iq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){re" ascii
    $s14 = "eturn \"NYh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}