rule _20160921_3065f95fdd47a96a00f0692965111ae8_20160921_be8454f98b5a_4841 {
  meta:
    description = "datamaliciousorder - from files 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash2       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"

  strings:
    $s1 = "tion fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return" ascii
    $s2 = "n \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s3 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){" ascii
    $s4 = "fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OP" ascii
    $s5 = "turn \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}