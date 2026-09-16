rule _20160921_71668d4dffd1de11d5c597a2f98e2266_20160921_83a4b9dfccb4_5391 {
  meta:
    description = "datamaliciousorder - from files 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_da7f7f057c35b886425ec822f654da90.js, 20160921_dc989bc33de845eef9826b241e933829.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash2       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash3       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash4       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash5       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"
    hash6       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"
    hash7       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "ion f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return " ascii
    $s2 = "(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(" ascii
    $s3 = "){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(" ascii
    $s4 = "000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn" ascii
    $s5 = "MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}