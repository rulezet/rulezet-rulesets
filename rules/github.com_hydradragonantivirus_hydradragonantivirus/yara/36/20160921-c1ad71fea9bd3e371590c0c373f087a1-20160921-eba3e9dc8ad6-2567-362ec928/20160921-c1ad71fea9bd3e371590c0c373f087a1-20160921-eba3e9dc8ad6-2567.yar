rule _20160921_c1ad71fea9bd3e371590c0c373f087a1_20160921_eba3e9dc8ad6_2567 {
  meta:
    description = "datamaliciousorder - from files 20160921_c1ad71fea9bd3e371590c0c373f087a1.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "on f000(){return \"Sv\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"" ascii
    $s2 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sj\";})(),(function f000(){retur" ascii
    $s3 = " f000(){return \"KDh\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"W" ascii
    $s4 = "function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Vj\";})(),(function f000(){retu" ascii
    $s5 = "n f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"D" ascii
    $s6 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(fun" ascii
    $s7 = "){return \"Sq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})" ascii
    $s8 = "),(function f000(){return \"KDh\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qj\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}