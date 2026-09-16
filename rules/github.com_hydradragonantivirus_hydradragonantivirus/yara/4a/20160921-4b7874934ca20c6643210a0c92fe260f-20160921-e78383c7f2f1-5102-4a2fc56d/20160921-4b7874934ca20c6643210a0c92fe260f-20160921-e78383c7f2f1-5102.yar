rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_e78383c7f2f1_5102 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1 = "TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ADy\";})(),(functi" ascii
    $s2 = "(function fuck(){return \"YQt\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){" ascii
    $s3 = "urn \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(f" ascii
    $s4 = "Sf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(functi" ascii
    $s5 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}