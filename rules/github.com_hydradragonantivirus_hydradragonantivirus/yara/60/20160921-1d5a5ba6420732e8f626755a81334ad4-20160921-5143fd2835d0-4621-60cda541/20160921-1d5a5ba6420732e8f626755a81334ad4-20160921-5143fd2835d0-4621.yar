rule _20160921_1d5a5ba6420732e8f626755a81334ad4_20160921_5143fd2835d0_4621 {
  meta:
    description = "datamaliciousorder - from files 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_5143fd2835d058f3854ef7b166166de4.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash2       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"
    hash3       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"
    hash4       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "{return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})" ascii
    $s2 = "(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";}" ascii
    $s3 = "i\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function" ascii
    $s4 = "turn \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s5 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}