rule _20160921_91734b00fd54cd3dd10c5f20c35d7864_20160921_c4afaa1e41ef_3984 {
  meta:
    description = "datamaliciousorder - from files 20160921_91734b00fd54cd3dd10c5f20c35d7864.js, 20160921_c4afaa1e41efa7633248f1941bda4010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"
    hash2       = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"

  strings:
    $s1 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return" ascii
    $s2 = "),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(" ascii
    $s3 = "Qr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZVi\";})(),(function" ascii
    $s4 = "Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(functio" ascii
    $s5 = "{return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s6 = "rn \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}