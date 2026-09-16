rule _20160921_c0cd20cf50e8d47fdd1303227435227a_20160921_df51150cb497_4051 {
  meta:
    description = "datamaliciousorder - from files 20160921_c0cd20cf50e8d47fdd1303227435227a.js, 20160921_df51150cb4977f20502f85bfda11d939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"
    hash2       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"

  strings:
    $s1 = " fuck(){return \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xw" ascii
    $s2 = "b\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(function" ascii
    $s3 = "{return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4 = "k(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"FJs\"" ascii
    $s5 = "k(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\"" ascii
    $s6 = "\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}