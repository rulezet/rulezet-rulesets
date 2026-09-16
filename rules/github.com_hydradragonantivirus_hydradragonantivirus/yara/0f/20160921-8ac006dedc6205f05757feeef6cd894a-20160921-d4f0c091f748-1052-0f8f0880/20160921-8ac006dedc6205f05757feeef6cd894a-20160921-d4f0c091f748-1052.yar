rule _20160921_8ac006dedc6205f05757feeef6cd894a_20160921_d4f0c091f748_1052 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_d4f0c091f748680e400a49909c223265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash2       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"

  strings:
    $s1  = "eturn \"Ot\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Iq\";})(),(" ascii
    $s2  = " f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Z" ascii
    $s3  = "0(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DIa\"" ascii
    $s4  = "PLy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(functi" ascii
    $s5  = "})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv\";})(),(function f000" ascii
    $s6  = "{return \"Oh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})()" ascii
    $s7  = " \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(funct" ascii
    $s8  = "on f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"" ascii
    $s9  = "ion f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s10 = "rn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"RPt\";})(),(" ascii
    $s11 = "ction f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})(),(function f000(){retur" ascii
    $s12 = "nction f000(){return \"Iq\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){retur" ascii
    $s13 = "ion f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s14 = "t\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(function" ascii
    $s15 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"Qp\";})(),(function f000(" ascii
    $s16 = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function" ascii
    $s17 = "ction f000(){return \"WIj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){retu" ascii
    $s18 = "ction f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}