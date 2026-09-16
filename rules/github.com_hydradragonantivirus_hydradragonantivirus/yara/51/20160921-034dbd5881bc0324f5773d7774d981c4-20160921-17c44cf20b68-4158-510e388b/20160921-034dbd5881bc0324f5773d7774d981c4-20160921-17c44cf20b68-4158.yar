rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_17c44cf20b68_4158 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash3       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"
    hash4       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash5       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"
    hash6       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = "fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq" ascii
    $s2 = "urn \"TTs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s3 = "(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(" ascii
    $s4 = "ction fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retur" ascii
    $s5 = "(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}