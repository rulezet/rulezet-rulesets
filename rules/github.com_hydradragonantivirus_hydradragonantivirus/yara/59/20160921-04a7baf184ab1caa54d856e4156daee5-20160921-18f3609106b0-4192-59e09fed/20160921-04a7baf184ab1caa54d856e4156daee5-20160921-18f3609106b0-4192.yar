rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_18f3609106b0_4192 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash3       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash4       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"
    hash5       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"
    hash6       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1 = "tion fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return" ascii
    $s2 = "{return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})" ascii
    $s3 = "})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fu" ascii
    $s4 = "on fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return " ascii
    $s5 = "eturn \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}