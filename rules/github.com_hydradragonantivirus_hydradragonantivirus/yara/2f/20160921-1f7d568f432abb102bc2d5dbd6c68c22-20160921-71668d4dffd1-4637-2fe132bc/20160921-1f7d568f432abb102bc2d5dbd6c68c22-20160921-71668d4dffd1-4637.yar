rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_71668d4dffd1_4637 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_dc989bc33de845eef9826b241e933829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash3       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash4       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"

  strings:
    $s1 = "\"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s2 = "unction f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s3 = "n\";})(),(function f000(){return \"Ug\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s4 = "ion f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return" ascii
    $s5 = ";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OMd\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}