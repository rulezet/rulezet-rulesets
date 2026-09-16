rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_71668d4dffd1_3449 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_dc989bc33de845eef9826b241e933829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash3       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash4       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash5       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"

  strings:
    $s1 = "eturn \"Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()," ascii
    $s2 = "0(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";}" ascii
    $s3 = "000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yz" ascii
    $s4 = "\"Lp\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s5 = "tion f000(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){retur" ascii
    $s6 = "){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"TRc\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}