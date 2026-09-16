rule _20160921_469953d9833167e141d9f086f1f41437_20160921_f7fa978ba93c_3716 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "uck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ar\"" ascii
    $s2 = "){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})()" ascii
    $s3 = "Kq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Hs\";})(),(functio" ascii
    $s4 = "){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";" ascii
    $s5 = "(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s6 = "nction fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}