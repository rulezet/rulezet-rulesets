rule _20160921_8a6f0879f250e6c15d2c7fa51d20505b_20160921_8dac417cb433_5497 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash2       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash3       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash4       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"
    hash5       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "eturn \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})()," ascii
    $s2 = "Ij\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function" ascii
    $s3 = "f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc" ascii
    $s4 = "\"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(funct" ascii
    $s5 = "ion f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}