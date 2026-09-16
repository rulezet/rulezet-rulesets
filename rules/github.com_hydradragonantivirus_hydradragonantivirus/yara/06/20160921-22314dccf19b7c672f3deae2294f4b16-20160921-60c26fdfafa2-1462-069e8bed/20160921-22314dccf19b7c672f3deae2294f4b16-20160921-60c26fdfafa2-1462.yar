rule _20160921_22314dccf19b7c672f3deae2294f4b16_20160921_60c26fdfafa2_1462 {
  meta:
    description = "datamaliciousorder - from files 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_60c26fdfafa2666b92246aea46e32175.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash2       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"

  strings:
    $s1  = ",(function f000(){return \"DYs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){r" ascii
    $s2  = "00(){return \"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\"" ascii
    $s3  = ";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTi\";})(),(function f0" ascii
    $s4  = "unction f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){retu" ascii
    $s5  = " f000(){return \"Oh\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KX" ascii
    $s6  = "\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function " ascii
    $s7  = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"P" ascii
    $s8  = "eturn \"PTs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})()," ascii
    $s9  = "ion f000(){return \"DYs\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s10 = "turn \"Qa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s11 = "eturn \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"QDg\";})(" ascii
    $s12 = "ction f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s13 = " f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DI" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}