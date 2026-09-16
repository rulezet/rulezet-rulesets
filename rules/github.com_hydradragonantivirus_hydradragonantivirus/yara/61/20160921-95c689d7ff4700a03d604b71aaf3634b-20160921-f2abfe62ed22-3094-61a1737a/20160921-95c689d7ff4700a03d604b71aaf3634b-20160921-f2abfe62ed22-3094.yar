rule _20160921_95c689d7ff4700a03d604b71aaf3634b_20160921_f2abfe62ed22_3094 {
  meta:
    description = "datamaliciousorder - from files 20160921_95c689d7ff4700a03d604b71aaf3634b.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"
    hash2       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = "ction fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){retu" ascii
    $s2 = "(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ai\";}" ascii
    $s3 = "(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MOj\";}" ascii
    $s4 = "{return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})" ascii
    $s5 = "tion fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retur" ascii
    $s6 = "eturn \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MOj\";})()" ascii
    $s7 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}