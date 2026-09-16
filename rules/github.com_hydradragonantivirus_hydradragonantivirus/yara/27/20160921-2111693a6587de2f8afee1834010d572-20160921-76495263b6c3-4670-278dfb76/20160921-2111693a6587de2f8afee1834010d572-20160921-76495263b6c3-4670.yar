rule _20160921_2111693a6587de2f8afee1834010d572_20160921_76495263b6c3_4670 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash3       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"
    hash4       = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"
    hash5       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = " fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"" ascii
    $s2 = "turn \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(" ascii
    $s3 = "ion fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s4 = "rn \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5 = "})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}