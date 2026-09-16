rule _20160921_91734b00fd54cd3dd10c5f20c35d7864_20160921_9eb4e3262a9b_5539 {
  meta:
    description = "datamaliciousorder - from files 20160921_91734b00fd54cd3dd10c5f20c35d7864.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"
    hash2       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"

  strings:
    $s1 = " fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s2 = "ion fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s3 = "(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck" ascii
    $s4 = "n \"Na\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(func" ascii
    $s5 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}