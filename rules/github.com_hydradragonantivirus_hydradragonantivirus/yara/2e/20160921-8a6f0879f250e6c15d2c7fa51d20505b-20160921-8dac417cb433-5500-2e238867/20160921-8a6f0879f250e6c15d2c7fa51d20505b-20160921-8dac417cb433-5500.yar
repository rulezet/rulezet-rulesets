rule _20160921_8a6f0879f250e6c15d2c7fa51d20505b_20160921_8dac417cb433_5500 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_bcf3911462135150c96c6b8eccf51628.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash2       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash3       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"
    hash4       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "eturn \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})()" ascii
    $s2 = "00(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s3 = "eturn \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"QDg\";})()" ascii
    $s4 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(" ascii
    $s5 = "\"QDg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Wb\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}