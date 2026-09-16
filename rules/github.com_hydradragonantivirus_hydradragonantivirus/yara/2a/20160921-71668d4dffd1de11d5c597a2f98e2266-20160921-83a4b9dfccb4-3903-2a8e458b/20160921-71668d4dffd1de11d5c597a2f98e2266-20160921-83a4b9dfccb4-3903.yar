rule _20160921_71668d4dffd1de11d5c597a2f98e2266_20160921_83a4b9dfccb4_3903 {
  meta:
    description = "datamaliciousorder - from files 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_dc989bc33de845eef9826b241e933829.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash2       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash3       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"
    hash4       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f0" ascii
    $s2 = "rn \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s3 = " f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"T" ascii
    $s4 = "Xg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s5 = "eturn \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(" ascii
    $s6 = ";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}