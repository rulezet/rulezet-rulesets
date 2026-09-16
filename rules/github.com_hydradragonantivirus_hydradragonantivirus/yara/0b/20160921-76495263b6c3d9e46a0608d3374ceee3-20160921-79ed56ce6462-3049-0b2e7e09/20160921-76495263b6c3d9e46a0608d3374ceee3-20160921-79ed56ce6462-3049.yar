rule _20160921_76495263b6c3d9e46a0608d3374ceee3_20160921_79ed56ce6462_3049 {
  meta:
    description = "datamaliciousorder - from files 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash2       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"
    hash3       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"

  strings:
    $s1 = "nction fuck(){return \"Yk\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s2 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Na\";})(),(function fuck(){ret" ascii
    $s3 = "ction fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retur" ascii
    $s4 = "{return \"We\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s5 = "){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";" ascii
    $s6 = "(){return \"Oh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";}" ascii
    $s7 = "rn \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Zy\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}