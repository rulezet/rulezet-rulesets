rule _20160921_8ac006dedc6205f05757feeef6cd894a_20160921_f1aea308b200_2534 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash2       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq" ascii
    $s2 = "tion f000(){return \"Vu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s3 = "})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(" ascii
    $s4 = "turn \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s5 = "000(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wb" ascii
    $s6 = "(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){re" ascii
    $s7 = "f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OMd" ascii
    $s8 = " \"DAp\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}