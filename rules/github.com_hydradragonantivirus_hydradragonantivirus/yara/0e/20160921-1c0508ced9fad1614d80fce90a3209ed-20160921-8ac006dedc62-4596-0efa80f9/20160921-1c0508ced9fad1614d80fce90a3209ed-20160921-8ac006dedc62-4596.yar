rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_8ac006dedc62_4596 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash3       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii
    $s2 = "),(function f000(){return \"ZIi\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Lp\";})(),(function f000()" ascii
    $s3 = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return " ascii
    $s4 = "Ij\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(function" ascii
    $s5 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Q" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}