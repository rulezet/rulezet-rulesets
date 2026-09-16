rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_105b4651b716_250 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_7463e4586b309c15d7048a37c63c1226.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash3       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash4       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash5       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"

  strings:
    $s1  = "on fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s2  = "tion fuck(){return \"UXf\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s3  = "ction fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return" ascii
    $s4  = "d\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s5  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return" ascii
    $s6  = " fuck(){return \"Et\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"I" ascii
    $s7  = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv" ascii
    $s8  = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return" ascii
    $s9  = "){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";}" ascii
    $s10 = "nction fuck(){return \"Pc\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii
    $s11 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return" ascii
    $s12 = "turn \"Zy\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s13 = "(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){" ascii
    $s14 = "tion fuck(){return \"Xg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s15 = "nction fuck(){return \"Nm\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return" ascii
    $s16 = "turn \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s17 = "unction fuck(){return \"Wo\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s18 = "k(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\"" ascii
    $s19 = "turn \"Yk\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(f" ascii
    $s20 = "(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}