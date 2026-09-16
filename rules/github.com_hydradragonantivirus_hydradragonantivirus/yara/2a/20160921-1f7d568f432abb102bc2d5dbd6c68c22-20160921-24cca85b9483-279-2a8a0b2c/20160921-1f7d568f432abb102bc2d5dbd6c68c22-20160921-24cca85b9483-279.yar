rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_24cca85b9483_279 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_ded524cdc972424d0fa8254648795d71.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash3       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash4       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash5       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash6       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash7       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"
    hash8       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"
    hash9       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"

  strings:
    $s1  = "000(){return \"Go\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn" ascii
    $s2  = "eturn \"Vj\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s3  = "on f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"" ascii
    $s4  = "Aa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s5  = "eturn \"MBb\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()," ascii
    $s6  = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return" ascii
    $s7  = "n \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"EZu\";})(),(fu" ascii
    $s8  = "nction f000(){return \"Mt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s9  = "00(){return \"RVb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s10 = "\"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MBb\";})(),(funct" ascii
    $s11 = "on f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s12 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(function f000" ascii
    $s13 = "return \"Br\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYs\";})(" ascii
    $s14 = "urn \"ZGq\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s15 = "ction f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s16 = "),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s17 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mt\";})(),(function f00" ascii
    $s18 = "0(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Um\";" ascii
    $s19 = "turn \"YTp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s20 = " f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}