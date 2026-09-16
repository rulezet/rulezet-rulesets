rule _20160921_7f682825ca903be9931443996a6639e7_20160921_be8454f98b5a_2126 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash2       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"
    hash3       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1 = ")(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fuck(" ascii
    $s2 = "l\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s3 = ",(function fuck(){return \"Jo\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){" ascii
    $s4 = "IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s5 = "on fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return " ascii
    $s6 = "(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";}" ascii
    $s7 = "n \"Xw\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xw\";})(),(funct" ascii
    $s8 = ",(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"AUx\";})(),(function fuck()" ascii
    $s9 = "eturn \"Wo0\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}