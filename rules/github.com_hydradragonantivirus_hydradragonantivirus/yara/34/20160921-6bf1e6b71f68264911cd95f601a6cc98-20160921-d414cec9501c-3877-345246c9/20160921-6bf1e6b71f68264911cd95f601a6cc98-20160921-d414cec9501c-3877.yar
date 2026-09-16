rule _20160921_6bf1e6b71f68264911cd95f601a6cc98_20160921_d414cec9501c_3877 {
  meta:
    description = "datamaliciousorder - from files 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash2       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"

  strings:
    $s1 = "nction fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s2 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Jg\";})(),(function f" ascii
    $s3 = ")(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s4 = " \"GJx\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s5 = "ion fuck(){return \"Yk\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s6 = "ck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}