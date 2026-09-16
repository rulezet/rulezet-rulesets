rule _20160921_9d32b55f93b83e117524c4df15361eee_20160921_dd28b3b2e4fa_4005 {
  meta:
    description = "datamaliciousorder - from files 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash2       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"
    hash3       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash4       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = "on f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"" ascii
    $s2 = "{return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(" ascii
    $s3 = "function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Vj\";})(),(function f000(){ret" ascii
    $s4 = "return \"ZGq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})()" ascii
    $s5 = "ion f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s6 = "Yx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}