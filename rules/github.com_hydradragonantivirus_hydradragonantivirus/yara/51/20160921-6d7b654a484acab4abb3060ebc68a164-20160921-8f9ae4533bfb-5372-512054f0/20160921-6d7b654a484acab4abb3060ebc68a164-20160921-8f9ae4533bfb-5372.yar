rule _20160921_6d7b654a484acab4abb3060ebc68a164_20160921_8f9ae4533bfb_5372 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_cd62091b54940830ea3695d380fd97d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash2       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash3       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"

  strings:
    $s1 = ",(function fuck(){return \"DAa\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){" ascii
    $s2 = " fuck(){return \"OQr\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UX" ascii
    $s3 = "rn \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(f" ascii
    $s4 = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){ret" ascii
    $s5 = "Qr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}