rule _20160921_76495263b6c3d9e46a0608d3374ceee3_20160921_79ed56ce6462_3916 {
  meta:
    description = "datamaliciousorder - from files 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js, 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_cd62091b54940830ea3695d380fd97d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash2       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"
    hash3       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash4       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"

  strings:
    $s1 = "})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s2 = "eturn \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(" ascii
    $s3 = "(){return \"Ml\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";}" ascii
    $s4 = "u\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function " ascii
    $s5 = "ck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx" ascii
    $s6 = "turn \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}