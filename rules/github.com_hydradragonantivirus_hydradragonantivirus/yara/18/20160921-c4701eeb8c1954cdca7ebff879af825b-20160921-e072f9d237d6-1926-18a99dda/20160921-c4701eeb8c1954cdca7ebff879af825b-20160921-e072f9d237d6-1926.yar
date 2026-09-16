rule _20160921_c4701eeb8c1954cdca7ebff879af825b_20160921_e072f9d237d6_1926 {
  meta:
    description = "datamaliciousorder - from files 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash2       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"

  strings:
    $s1  = "{return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Mw\";})()" ascii
    $s2  = "uck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GN" ascii
    $s3  = "(){return \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";" ascii
    $s4  = "ck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\"" ascii
    $s5  = " \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(funct" ascii
    $s6  = "),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck()" ascii
    $s7  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return" ascii
    $s8  = "urn \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Pc\";})(),(" ascii
    $s9  = "){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";}" ascii
    $s10 = "rn \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}