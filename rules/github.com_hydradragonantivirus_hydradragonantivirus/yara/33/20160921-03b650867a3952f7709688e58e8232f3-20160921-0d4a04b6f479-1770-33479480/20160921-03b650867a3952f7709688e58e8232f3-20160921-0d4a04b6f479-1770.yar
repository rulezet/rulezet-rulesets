rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_0d4a04b6f479_1770 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash3       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash4       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"

  strings:
    $s1  = "),(function fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(" ascii
    $s2  = "nction fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retu" ascii
    $s3  = "UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OPz\";})(),(functi" ascii
    $s4  = " fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"I" ascii
    $s5  = "(function fuck(){return \"OQr\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){re" ascii
    $s6  = "rn \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(f" ascii
    $s7  = "(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";" ascii
    $s8  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s9  = "urn \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(f" ascii
    $s10 = "OQr\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}