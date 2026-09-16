rule _20160921_2b38530ecae3735e98453e56dd7a0292_20160921_48288731baa0_4805 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b38530ecae3735e98453e56dd7a0292.js, 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f1595f803e301ed13d99315b244aac664f908c0c0d8ab508c1d104bf7ae947"
    hash2       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash3       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash4       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash5       = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"

  strings:
    $s1 = "(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(" ascii
    $s2 = "ck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\"" ascii
    $s3 = "Dy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(functio" ascii
    $s4 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return " ascii
    $s5 = "urn \"XFd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}