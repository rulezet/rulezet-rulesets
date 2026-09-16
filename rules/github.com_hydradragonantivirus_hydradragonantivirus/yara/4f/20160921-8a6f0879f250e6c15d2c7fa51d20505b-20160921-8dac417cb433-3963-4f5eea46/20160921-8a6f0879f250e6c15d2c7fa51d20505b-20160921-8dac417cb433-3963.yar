rule _20160921_8a6f0879f250e6c15d2c7fa51d20505b_20160921_8dac417cb433_3963 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash2       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash3       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"
    hash4       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"

  strings:
    $s1 = ",(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){" ascii
    $s2 = "\"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s3 = " f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"M" ascii
    $s4 = "on f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"D" ascii
    $s5 = "){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";}" ascii
    $s6 = "Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}