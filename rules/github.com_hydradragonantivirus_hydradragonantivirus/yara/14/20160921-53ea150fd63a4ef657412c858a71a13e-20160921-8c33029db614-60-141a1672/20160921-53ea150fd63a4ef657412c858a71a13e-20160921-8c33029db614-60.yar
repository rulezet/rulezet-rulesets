rule _20160921_53ea150fd63a4ef657412c858a71a13e_20160921_8c33029db614_60 {
  meta:
    description = "datamaliciousorder - from files 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash2       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash3       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"

  strings:
    $s1  = "WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(funct" ascii
    $s2  = "Tn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s3  = "eturn \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(" ascii
    $s4  = "return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(" ascii
    $s5  = "){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(" ascii
    $s6  = ",(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){" ascii
    $s7  = "urn \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s8  = "nction f000(){return \"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s9  = "000(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\"" ascii
    $s10 = "eturn \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})()," ascii
    $s11 = "00(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\"" ascii
    $s12 = "),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s13 = "\"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"DIa\";})(),(func" ascii
    $s14 = "TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s15 = "return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"RPt\";})(" ascii
    $s16 = ")(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000" ascii
    $s17 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s18 = "tion f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function f000(){return " ascii
    $s19 = " f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s20 = "{return \"DYs\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Vj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}