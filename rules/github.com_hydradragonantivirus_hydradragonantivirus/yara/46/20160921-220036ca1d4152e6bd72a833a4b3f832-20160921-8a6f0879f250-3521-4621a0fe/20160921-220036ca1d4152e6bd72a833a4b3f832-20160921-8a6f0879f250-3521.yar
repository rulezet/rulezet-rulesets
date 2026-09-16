rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_8a6f0879f250_3521 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash3       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash4       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "rn \"Sq\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s2 = "n \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(fun" ascii
    $s3 = ")(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f00" ascii
    $s4 = "on f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"G" ascii
    $s5 = "000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Do\"" ascii
    $s6 = "rn \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KDh\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}