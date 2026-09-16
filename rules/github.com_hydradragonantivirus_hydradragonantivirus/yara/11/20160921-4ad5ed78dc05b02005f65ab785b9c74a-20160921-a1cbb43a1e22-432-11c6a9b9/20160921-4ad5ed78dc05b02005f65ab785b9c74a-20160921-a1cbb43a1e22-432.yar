rule _20160921_4ad5ed78dc05b02005f65ab785b9c74a_20160921_a1cbb43a1e22_432 {
  meta:
    description = "datamaliciousorder - from files 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash2       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash3       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1  = "\"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(funct" ascii
    $s2  = "ction f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){retur" ascii
    $s3  = "rn \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s4  = "\"Wb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s5  = "rn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(fu" ascii
    $s6  = "{return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})" ascii
    $s7  = "rn \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s8  = "\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f" ascii
    $s9  = "Xg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s10 = " f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TR" ascii
    $s11 = "WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZGq\";})(),(funct" ascii
    $s12 = "nction f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(function f000(){retu" ascii
    $s13 = "ction f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s14 = "urn \"Qj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"KXg\";})(),(" ascii
    $s15 = "f000(){return \"Go\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj" ascii
    $s16 = "nction f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"RPt\";})(),(function f000(){retu" ascii
    $s17 = " f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Q" ascii
    $s18 = "\"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s19 = "n \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Lp\";})(),(fun" ascii
    $s20 = "rn \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}