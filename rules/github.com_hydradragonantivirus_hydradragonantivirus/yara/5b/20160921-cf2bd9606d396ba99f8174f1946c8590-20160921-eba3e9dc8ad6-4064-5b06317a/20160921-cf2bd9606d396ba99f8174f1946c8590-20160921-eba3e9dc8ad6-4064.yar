rule _20160921_cf2bd9606d396ba99f8174f1946c8590_20160921_eba3e9dc8ad6_4064 {
  meta:
    description = "datamaliciousorder - from files 20160921_cf2bd9606d396ba99f8174f1946c8590.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(functio" ascii
    $s2 = "unction f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii
    $s3 = "0(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";" ascii
    $s4 = ",(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){r" ascii
    $s5 = " \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(func" ascii
    $s6 = ")(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}