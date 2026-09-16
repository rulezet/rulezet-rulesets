rule _20160921_73310531aa4a1df7337a6ef42003ce5e_20160921_7e2de7c26f13_1895 {
  meta:
    description = "datamaliciousorder - from files 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_7e2de7c26f136a1a958818752613cac3.js, 20160921_97811319fb50bbd834b521ddcbb35712.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash2       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"
    hash3       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"

  strings:
    $s1  = "tion fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2  = "Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LLv\";})(),(functi" ascii
    $s3  = "(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";" ascii
    $s4  = "function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){re" ascii
    $s5  = "ck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf" ascii
    $s6  = "(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s7  = "n fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"" ascii
    $s8  = "(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ADy\";}" ascii
    $s9  = "eturn \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s10 = "n fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}