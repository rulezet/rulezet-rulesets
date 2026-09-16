rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_1af58d123175_3171 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash3       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash4       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = "f000(){return \"Um\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx" ascii
    $s2 = "),(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){" ascii
    $s3 = "on f000(){return \"RVb\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"" ascii
    $s4 = "return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})" ascii
    $s5 = "tion f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){retur" ascii
    $s6 = "turn \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"MMz\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}