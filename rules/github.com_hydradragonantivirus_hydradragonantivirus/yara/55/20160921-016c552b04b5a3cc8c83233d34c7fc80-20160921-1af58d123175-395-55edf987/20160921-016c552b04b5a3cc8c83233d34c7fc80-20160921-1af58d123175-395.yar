rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_1af58d123175_395 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash3       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"

  strings:
    $s1  = "n f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s2  = "n f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Z" ascii
    $s3  = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s4  = "\"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s5  = "){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})" ascii
    $s6  = "\"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(func" ascii
    $s7  = "rn \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(fun" ascii
    $s8  = "eturn \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})()" ascii
    $s9  = "n \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s10 = "rn \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(" ascii
    $s11 = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"XTn\";})(),(function f000" ascii
    $s12 = "n f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s13 = "return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})()" ascii
    $s14 = "0(){return \"Wb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";" ascii
    $s15 = "turn \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(f" ascii
    $s16 = "\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f0" ascii
    $s17 = "rn \"Wb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(fu" ascii
    $s18 = "){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})" ascii
    $s19 = "{return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"ZGq\";})" ascii
    $s20 = "turn \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Mc\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}