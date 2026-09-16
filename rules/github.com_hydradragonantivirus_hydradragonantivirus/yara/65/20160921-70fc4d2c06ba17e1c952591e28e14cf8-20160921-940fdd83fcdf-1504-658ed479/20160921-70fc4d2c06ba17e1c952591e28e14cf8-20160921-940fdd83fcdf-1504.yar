rule _20160921_70fc4d2c06ba17e1c952591e28e14cf8_20160921_940fdd83fcdf_1504 {
  meta:
    description = "datamaliciousorder - from files 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash2       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash3       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"
    hash4       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1  = " fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"M" ascii
    $s2  = "k(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GJx" ascii
    $s3  = "k(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\"" ascii
    $s4  = " \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s5  = "Pu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s6  = "unction fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){ret" ascii
    $s7  = "){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})" ascii
    $s8  = "MBg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Vb\";})(),(function" ascii
    $s9  = "{return \"EHo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s10 = "n \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(fu" ascii
    $s11 = " \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(fun" ascii
    $s12 = "{return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})" ascii
    $s13 = "uck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}