rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_70fc4d2c06ba_5100 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash3       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"
    hash4       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1 = "ck(){return \"GNm\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv" ascii
    $s2 = "(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\"" ascii
    $s3 = "ck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\"" ascii
    $s4 = "n \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(fun" ascii
    $s5 = "unction fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}