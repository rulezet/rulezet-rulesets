rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_962ed1e894cd_5098 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_962ed1e894cd91f421ad984310ce3140.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"

  strings:
    $s1 = "ction fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){retu" ascii
    $s2 = "\"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(fun" ascii
    $s3 = "{return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";}" ascii
    $s4 = "(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){" ascii
    $s5 = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}