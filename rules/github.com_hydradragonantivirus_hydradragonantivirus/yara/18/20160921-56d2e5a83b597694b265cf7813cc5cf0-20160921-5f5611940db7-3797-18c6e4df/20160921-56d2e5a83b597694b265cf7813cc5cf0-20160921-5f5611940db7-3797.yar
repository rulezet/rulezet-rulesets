rule _20160921_56d2e5a83b597694b265cf7813cc5cf0_20160921_5f5611940db7_3797 {
  meta:
    description = "datamaliciousorder - from files 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash2       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash3       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash4       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash5       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"

  strings:
    $s1 = "\"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(funct" ascii
    $s2 = "\"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(funct" ascii
    $s3 = "0(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";" ascii
    $s4 = " \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(func" ascii
    $s5 = "\"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(func" ascii
    $s6 = "),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}