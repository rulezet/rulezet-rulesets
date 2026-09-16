rule _20160921_5745920040b3b3273f05bcfbefadb4d8_20160921_5c25506bc44b_2972 {
  meta:
    description = "datamaliciousorder - from files 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_5c25506bc44b50a0c8028dec6521139d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash2       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"

  strings:
    $s1 = "rn \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(fu" ascii
    $s2 = "{return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s3 = " fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IP" ascii
    $s4 = "uck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IP" ascii
    $s5 = " \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(fu" ascii
    $s6 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"" ascii
    $s7 = "on fuck(){return \"Ml\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}