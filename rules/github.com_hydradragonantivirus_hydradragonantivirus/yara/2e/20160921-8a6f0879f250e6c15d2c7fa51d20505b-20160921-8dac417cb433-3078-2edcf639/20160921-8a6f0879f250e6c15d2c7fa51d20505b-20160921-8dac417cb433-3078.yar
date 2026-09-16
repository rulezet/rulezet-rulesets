rule _20160921_8a6f0879f250e6c15d2c7fa51d20505b_20160921_8dac417cb433_3078 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c459056d51b1a4ea3176139800021b35.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash2       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash3       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"
    hash4       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "(),(function f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Ml\";})(),(function f000(" ascii
    $s2 = "){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(" ascii
    $s3 = " \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(fun" ascii
    $s4 = "ction f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){retur" ascii
    $s5 = "(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";" ascii
    $s6 = "PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(functio" ascii
    $s7 = "n f000(){return \"Qz\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"W" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}