rule _20160921_db727bb0ba7a4addd64ea2ef7f7475f0_20160921_e78383c7f2f1_2169 {
  meta:
    description = "datamaliciousorder - from files 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1 = "turn \"GJx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s2 = "})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(" ascii
    $s3 = "turn \"XHj\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s4 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return " ascii
    $s5 = "),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(" ascii
    $s6 = "),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck()" ascii
    $s7 = "\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s8 = ")(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fuc" ascii
    $s9 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}