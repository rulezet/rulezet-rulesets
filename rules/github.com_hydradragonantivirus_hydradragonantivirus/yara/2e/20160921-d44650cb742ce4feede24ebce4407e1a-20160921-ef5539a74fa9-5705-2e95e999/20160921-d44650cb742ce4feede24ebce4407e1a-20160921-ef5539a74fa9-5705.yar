rule _20160921_d44650cb742ce4feede24ebce4407e1a_20160921_ef5539a74fa9_5705 {
  meta:
    description = "datamaliciousorder - from files 20160921_d44650cb742ce4feede24ebce4407e1a.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"
    hash2       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"

  strings:
    $s1 = "rn \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s2 = "r\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function" ascii
    $s3 = "(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\"" ascii
    $s4 = "ction fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s5 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}