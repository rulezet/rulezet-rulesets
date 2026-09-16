rule _20160921_994c4aa8813658fbb0b792d8aa221e53_20160921_e30a7fc515c8_4002 {
  meta:
    description = "datamaliciousorder - from files 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash2       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash3       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "tion f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s2 = "0(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";}" ascii
    $s3 = "eturn \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()," ascii
    $s4 = "0(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";" ascii
    $s5 = "urn \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(fu" ascii
    $s6 = "000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}