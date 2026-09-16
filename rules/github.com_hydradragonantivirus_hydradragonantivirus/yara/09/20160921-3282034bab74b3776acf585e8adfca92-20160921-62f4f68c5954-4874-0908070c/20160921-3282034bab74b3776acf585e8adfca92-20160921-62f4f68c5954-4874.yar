rule _20160921_3282034bab74b3776acf585e8adfca92_20160921_62f4f68c5954_4874 {
  meta:
    description = "datamaliciousorder - from files 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_62f4f68c59540f36d255485f0f0e37c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash2       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"

  strings:
    $s1 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return " ascii
    $s2 = "ck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";" ascii
    $s3 = "rn \"Hs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(fu" ascii
    $s4 = "{return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ve\";})(" ascii
    $s5 = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}