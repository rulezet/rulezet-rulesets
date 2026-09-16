rule _20160921_73310531aa4a1df7337a6ef42003ce5e_20160921_97811319fb50_5400 {
  meta:
    description = "datamaliciousorder - from files 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash2       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash3       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"

  strings:
    $s1 = " \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s2 = "on fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){retur" ascii
    $s4 = "\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jg\";})(),(function f" ascii
    $s5 = "k(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}