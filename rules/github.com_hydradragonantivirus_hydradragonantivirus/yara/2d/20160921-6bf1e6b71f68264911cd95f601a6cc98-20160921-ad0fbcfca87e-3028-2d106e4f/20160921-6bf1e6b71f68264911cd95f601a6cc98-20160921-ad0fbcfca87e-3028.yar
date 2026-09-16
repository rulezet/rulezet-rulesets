rule _20160921_6bf1e6b71f68264911cd95f601a6cc98_20160921_ad0fbcfca87e_3028 {
  meta:
    description = "datamaliciousorder - from files 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash2       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"

  strings:
    $s1 = "n fuck(){return \"Ai\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s2 = "ion fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return " ascii
    $s3 = "})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})(),(function fuck" ascii
    $s4 = "ck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ADy" ascii
    $s5 = "Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(functio" ascii
    $s6 = "){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(" ascii
    $s7 = "function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}