rule _20160921_71668d4dffd1de11d5c597a2f98e2266_20160921_83a4b9dfccb4_5392 {
  meta:
    description = "datamaliciousorder - from files 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_c459056d51b1a4ea3176139800021b35.js, 20160921_dc989bc33de845eef9826b241e933829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash2       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash3       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"
    hash4       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"

  strings:
    $s1 = "000(){return \"Qa\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s2 = "rn \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fu" ascii
    $s3 = "QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(functi" ascii
    $s4 = " \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(fu" ascii
    $s5 = "{return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}