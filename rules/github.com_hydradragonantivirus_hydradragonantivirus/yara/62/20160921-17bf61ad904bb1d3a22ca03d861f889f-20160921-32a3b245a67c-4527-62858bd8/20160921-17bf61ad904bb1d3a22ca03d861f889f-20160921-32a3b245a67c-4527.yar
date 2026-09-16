rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_32a3b245a67c_4527 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash3       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash4       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash5       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "(){return \"Wo\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";" ascii
    $s2 = "urn \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})()," ascii
    $s3 = "n \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s4 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Sx\"" ascii
    $s5 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"S" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}