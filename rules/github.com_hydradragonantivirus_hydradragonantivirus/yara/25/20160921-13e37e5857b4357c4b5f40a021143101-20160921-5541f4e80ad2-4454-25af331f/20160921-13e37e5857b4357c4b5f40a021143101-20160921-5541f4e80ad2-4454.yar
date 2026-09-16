rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_5541f4e80ad2_4454 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"

  strings:
    $s1 = "g\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s2 = "b\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s3 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){ret" ascii
    $s4 = "){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(" ascii
    $s5 = "function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}