rule _20160921_62f4f68c59540f36d255485f0f0e37c9_20160921_76495263b6c3_3852 {
  meta:
    description = "datamaliciousorder - from files 20160921_62f4f68c59540f36d255485f0f0e37c9.js, 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"
    hash2       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash3       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"

  strings:
    $s1 = "return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s2 = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){retu" ascii
    $s3 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){" ascii
    $s4 = "),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck()" ascii
    $s5 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retur" ascii
    $s6 = "return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"GNm\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}