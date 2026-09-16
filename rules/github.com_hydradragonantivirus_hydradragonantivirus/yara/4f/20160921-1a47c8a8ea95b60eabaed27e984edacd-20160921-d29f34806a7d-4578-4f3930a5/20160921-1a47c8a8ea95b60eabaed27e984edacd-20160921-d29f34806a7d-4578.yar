rule _20160921_1a47c8a8ea95b60eabaed27e984edacd_20160921_d29f34806a7d_4578 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash2       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"
    hash3       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = "Rn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(functi" ascii
    $s2 = "(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\"" ascii
    $s3 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s4 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){ret" ascii
    $s5 = ",(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}