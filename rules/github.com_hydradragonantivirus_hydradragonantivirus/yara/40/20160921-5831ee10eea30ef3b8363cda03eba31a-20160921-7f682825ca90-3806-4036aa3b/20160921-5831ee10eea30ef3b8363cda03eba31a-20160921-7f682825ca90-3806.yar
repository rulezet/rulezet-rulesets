rule _20160921_5831ee10eea30ef3b8363cda03eba31a_20160921_7f682825ca90_3806 {
  meta:
    description = "datamaliciousorder - from files 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash2       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash3       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1 = "eturn \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s2 = "turn \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s3 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s4 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return " ascii
    $s5 = "unction fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retu" ascii
    $s6 = "(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}