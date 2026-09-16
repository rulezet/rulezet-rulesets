rule _20160921_994c4aa8813658fbb0b792d8aa221e53_20160921_f9054cc04d83_5582 {
  meta:
    description = "datamaliciousorder - from files 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"
    hash4       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "n f000(){return \"KDh\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"" ascii
    $s2 = "0(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"KXg" ascii
    $s3 = "n \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s4 = "n\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"ZGq\";})(),(functio" ascii
    $s5 = "(function f000(){return \"Tb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}