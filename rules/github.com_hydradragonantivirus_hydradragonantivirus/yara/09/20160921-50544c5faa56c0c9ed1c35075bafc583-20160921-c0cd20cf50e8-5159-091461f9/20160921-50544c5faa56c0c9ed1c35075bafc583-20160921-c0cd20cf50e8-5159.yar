rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_c0cd20cf50e8_5159 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_c0cd20cf50e8d47fdd1303227435227a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"

  strings:
    $s1 = "return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Pc\";})()," ascii
    $s2 = "on fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s3 = "uck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\"" ascii
    $s4 = "nction fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){retur" ascii
    $s5 = "uck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}