rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_c6543124cf42_1804 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash3       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1  = "{return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qj\";})(" ascii
    $s2  = ",(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){" ascii
    $s3  = "ion f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii
    $s4  = "\"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Qz\";})(),(funct" ascii
    $s5  = "rn \"BMj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(f" ascii
    $s6  = " \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(fu" ascii
    $s7  = "turn \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})()," ascii
    $s8  = "f000(){return \"TKp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RL" ascii
    $s9  = "n f000(){return \"ZFe\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s10 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sv\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}