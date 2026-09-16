rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_a96b471e778a_1680 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_a96b471e778a8101c168e06727d930fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"

  strings:
    $s1  = "eturn \"XHj\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s2  = " \"DAa\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s3  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){" ascii
    $s4  = "eturn \"Fv\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Xw\";})(),(" ascii
    $s5  = "(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"ADy\";}" ascii
    $s6  = "tion fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s7  = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jh\";})(),(fun" ascii
    $s8  = "n \"CCb\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s9  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return " ascii
    $s10 = "urn \"XCr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s11 = "(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}