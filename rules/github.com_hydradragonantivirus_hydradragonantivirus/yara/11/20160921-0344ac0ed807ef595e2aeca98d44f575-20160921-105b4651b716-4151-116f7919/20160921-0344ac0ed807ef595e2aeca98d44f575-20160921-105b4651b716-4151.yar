rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_105b4651b716_4151 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_105b4651b7160ca47c8bc86d4da31c43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"

  strings:
    $s1 = "k(){return \"DWe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\"" ascii
    $s2 = "k(){return \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh\";}" ascii
    $s3 = "(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";" ascii
    $s4 = "turn \"Hs\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s5 = "})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}