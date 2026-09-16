rule _20160921_5f7be0b4d162caa40e1fc5a06f9f867a_20160921_91734b00fd54_5288 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash2       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"

  strings:
    $s1 = "ion fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s2 = "ck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\"" ascii
    $s3 = "ion fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s4 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){retu" ascii
    $s5 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}