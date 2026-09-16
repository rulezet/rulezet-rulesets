rule _20160921_68d4a1cff7c2dbc758cf0077184d0d52_20160921_aaf08d1a7081_3868 {
  meta:
    description = "datamaliciousorder - from files 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash2       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"

  strings:
    $s1 = "){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wy\";})" ascii
    $s2 = "})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f00" ascii
    $s3 = "n f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"W" ascii
    $s4 = "ction f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){retur" ascii
    $s5 = "){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";}" ascii
    $s6 = "return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}