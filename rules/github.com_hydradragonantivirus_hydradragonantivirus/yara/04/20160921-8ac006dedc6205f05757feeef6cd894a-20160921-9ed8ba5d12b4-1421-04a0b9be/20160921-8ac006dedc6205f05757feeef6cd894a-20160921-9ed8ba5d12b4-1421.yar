rule _20160921_8ac006dedc6205f05757feeef6cd894a_20160921_9ed8ba5d12b4_1421 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash2       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"

  strings:
    $s1  = " f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"I" ascii
    $s2  = "rn \"KDh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s3  = "eturn \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})()" ascii
    $s4  = ")(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000" ascii
    $s5  = "ction f000(){return \"MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){retu" ascii
    $s6  = "f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s7  = "urn \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s8  = "\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(function " ascii
    $s9  = "ion f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s10 = "0(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn" ascii
    $s11 = "000(){return \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc" ascii
    $s12 = "return \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})" ascii
    $s13 = "ion f000(){return \"Nx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s14 = "(){return \"DYs\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"TRc\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}