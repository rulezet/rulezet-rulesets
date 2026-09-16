rule _20160921_994c4aa8813658fbb0b792d8aa221e53_20160922_7706788d6039_69 {
  meta:
    description = "datamaliciousorder - from files 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash2       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1  = "n f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"B" ascii
    $s2  = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000" ascii
    $s3  = "00(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s4  = "00(){return \"Wb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\"" ascii
    $s5  = "on f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"" ascii
    $s6  = "ction f000(){return \"PTi\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wb\";})(),(function f000(){retur" ascii
    $s7  = "f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"O" ascii
    $s8  = "nction f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){retur" ascii
    $s9  = "\"RVb\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s10 = "(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";" ascii
    $s11 = "0(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"TKl\";}" ascii
    $s12 = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(" ascii
    $s13 = "){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";" ascii
    $s14 = ")(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii
    $s15 = " \"Mt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(funct" ascii
    $s16 = "x\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function " ascii
    $s17 = " \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s18 = "(function f000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yi\";})(),(function f000(){re" ascii
    $s19 = "turn \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s20 = "rn \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}