rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_5745920040b3_2703 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_5745920040b3b3273f05bcfbefadb4d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"

  strings:
    $s1 = "e\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(functio" ascii
    $s2 = "Yk\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s3 = "ction fuck(){return \"Ik\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s4 = "uck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av\"" ascii
    $s5 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retur" ascii
    $s6 = "(){return \"CTm\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Ai\";})" ascii
    $s7 = "){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}