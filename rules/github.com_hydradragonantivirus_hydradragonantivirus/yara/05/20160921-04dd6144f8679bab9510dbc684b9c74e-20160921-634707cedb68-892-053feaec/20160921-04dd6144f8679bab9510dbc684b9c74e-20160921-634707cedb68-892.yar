rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_634707cedb68_892 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash3       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash4       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1  = "){return \"Ml\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(" ascii
    $s2  = "ion f000(){return \"IPu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s3  = "nction f000(){return \"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii
    $s4  = "GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(functio" ascii
    $s5  = "0(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\"" ascii
    $s6  = "i\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OMd\";})(),(function" ascii
    $s7  = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(),(functio" ascii
    $s8  = "n f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return " ascii
    $s9  = "){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})" ascii
    $s10 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s11 = "\"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s12 = "f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\"" ascii
    $s13 = "nction f000(){return \"Oe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s14 = "0(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa" ascii
    $s15 = "00(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";" ascii
    $s16 = "\"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s17 = "000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc" ascii
    $s18 = "(),(function f000(){return \"DYs\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Kw\";})(),(function f000()" ascii
    $s19 = " f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"W" ascii
    $s20 = "f000(){return \"Qa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}