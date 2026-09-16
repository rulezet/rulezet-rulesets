rule _20160921_6ed03f6116d83dcb603f8d7a421669a9_20160921_71668d4dffd1_1410 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_dc989bc33de845eef9826b241e933829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash2       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash3       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash4       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash5       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"

  strings:
    $s1  = "n f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s2  = "00(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa" ascii
    $s3  = "eturn \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})()," ascii
    $s4  = "Fe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(functio" ascii
    $s5  = "){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";}" ascii
    $s6  = "f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZF" ascii
    $s7  = "f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s8  = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s9  = ",(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){r" ascii
    $s10 = "rn \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(" ascii
    $s11 = "ction f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){retur" ascii
    $s12 = "(),(function f000(){return \"Ml\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s13 = "rn \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(fu" ascii
    $s14 = ";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}