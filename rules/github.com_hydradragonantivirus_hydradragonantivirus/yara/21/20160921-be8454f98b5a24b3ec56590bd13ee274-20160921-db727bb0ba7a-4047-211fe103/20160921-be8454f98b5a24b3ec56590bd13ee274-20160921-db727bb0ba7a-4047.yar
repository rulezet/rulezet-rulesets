rule _20160921_be8454f98b5a24b3ec56590bd13ee274_20160921_db727bb0ba7a_4047 {
  meta:
    description = "datamaliciousorder - from files 20160921_be8454f98b5a24b3ec56590bd13ee274.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"
    hash2       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"

  strings:
    $s1 = "(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"XFd\";})(),(function fuck(" ascii
    $s2 = ")(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ADy\";})(),(function fuck" ascii
    $s3 = "uck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQ" ascii
    $s4 = "turn \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(" ascii
    $s5 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(fu" ascii
    $s6 = "),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}