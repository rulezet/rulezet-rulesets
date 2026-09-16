rule _20160921_56560f8d7ec61c150afb741a4a7975e2_20160921_ede755ec6df0_5207 {
  meta:
    description = "datamaliciousorder - from files 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash2       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"
    hash3       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1 = "(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";" ascii
    $s2 = "b\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s3 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(" ascii
    $s5 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}