rule _20160921_6bf1e6b71f68264911cd95f601a6cc98_20160921_93920c7f8d8d_1735 {
  meta:
    description = "datamaliciousorder - from files 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash2       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"

  strings:
    $s1  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo" ascii
    $s2  = "(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\"" ascii
    $s3  = "rn \"Ai\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s4  = "turn \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(" ascii
    $s5  = "){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})" ascii
    $s6  = "turn \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s7  = "nction fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){ret" ascii
    $s8  = "unction fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s9  = " \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(funct" ascii
    $s10 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Zy" ascii
    $s11 = "ction fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}