rule _20160921_510713862e5c8c05841e5272407127f3_20160921_dd3003e8f162_5166 {
  meta:
    description = "datamaliciousorder - from files 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash2       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"

  strings:
    $s1 = "eturn \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s2 = ")(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuc" ascii
    $s3 = "turn \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s4 = " fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DR" ascii
    $s5 = "\"DRx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}