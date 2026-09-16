rule _20160921_3d83b7982fc59266194f048e87fb066d_20160921_5745920040b3_5011 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_5745920040b3b3273f05bcfbefadb4d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash2       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"

  strings:
    $s1 = "uck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb" ascii
    $s2 = "{return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})" ascii
    $s3 = "\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function " ascii
    $s4 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){" ascii
    $s5 = ";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}