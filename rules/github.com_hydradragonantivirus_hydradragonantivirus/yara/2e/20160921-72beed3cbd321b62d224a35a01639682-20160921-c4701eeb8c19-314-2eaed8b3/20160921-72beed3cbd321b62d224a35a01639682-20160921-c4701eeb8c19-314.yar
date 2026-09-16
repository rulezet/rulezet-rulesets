rule _20160921_72beed3cbd321b62d224a35a01639682_20160921_c4701eeb8c19_314 {
  meta:
    description = "datamaliciousorder - from files 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash2       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash3       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1  = "turn \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s2  = "eturn \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})()" ascii
    $s3  = "return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s4  = "\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function" ascii
    $s5  = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){retu" ascii
    $s6  = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s7  = "(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\"" ascii
    $s8  = "eturn \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s9  = "urn \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(f" ascii
    $s10 = " \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s11 = "function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){ret" ascii
    $s12 = ";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fu" ascii
    $s13 = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s14 = "\"Oh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(funct" ascii
    $s15 = "return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s16 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s17 = "return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})()," ascii
    $s18 = "ion fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return" ascii
    $s19 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\"" ascii
    $s20 = "uck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LG" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}