rule _20160921_8ac006dedc6205f05757feeef6cd894a_20160921_f7b964e1d5b6_1911 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash2       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"

  strings:
    $s1  = "on f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return " ascii
    $s2  = "turn \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(" ascii
    $s3  = "tion f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s4  = "on f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s5  = "nction f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})(),(function f000(){retur" ascii
    $s6  = "urn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(" ascii
    $s7  = ";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f00" ascii
    $s8  = "return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(" ascii
    $s9  = "000(){return \"Lp\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp" ascii
    $s10 = "tion f000(){return \"WIj\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"PTs\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}