rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_1af58d123175_4120 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash3       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"

  strings:
    $s1 = "00(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";" ascii
    $s2 = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SE" ascii
    $s3 = "return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})()," ascii
    $s4 = "eturn \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(" ascii
    $s5 = "tion f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}