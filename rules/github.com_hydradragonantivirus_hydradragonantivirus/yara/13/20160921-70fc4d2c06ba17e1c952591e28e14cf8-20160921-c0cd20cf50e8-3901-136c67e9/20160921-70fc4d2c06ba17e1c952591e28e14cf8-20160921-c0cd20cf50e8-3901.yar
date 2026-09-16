rule _20160921_70fc4d2c06ba17e1c952591e28e14cf8_20160921_c0cd20cf50e8_3901 {
  meta:
    description = "datamaliciousorder - from files 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_c0cd20cf50e8d47fdd1303227435227a.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash2       = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"
    hash3       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"
    hash4       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1 = "nction fuck(){return \"CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retu" ascii
    $s2 = "(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OPz\";})(),(function fuck(" ascii
    $s3 = "urn \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s4 = "rn \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(fu" ascii
    $s5 = "f\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(function " ascii
    $s6 = "on fuck(){return \"OQr\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}