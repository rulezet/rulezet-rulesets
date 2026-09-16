rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_2bac0af1f20f_1763 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"

  strings:
    $s1  = "n \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(fu" ascii
    $s2  = "return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"QTc\";})(" ascii
    $s3  = "nction fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s4  = "})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(" ascii
    $s5  = "n fuck(){return \"DWe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"" ascii
    $s6  = "(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Ik\";})(),(function fuck()" ascii
    $s7  = "fuck(){return \"DWe\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"M" ascii
    $s8  = "urn \"DWe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(f" ascii
    $s9  = "function fuck(){return \"Yk\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){ret" ascii
    $s10 = "nction fuck(){return \"Ot\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}