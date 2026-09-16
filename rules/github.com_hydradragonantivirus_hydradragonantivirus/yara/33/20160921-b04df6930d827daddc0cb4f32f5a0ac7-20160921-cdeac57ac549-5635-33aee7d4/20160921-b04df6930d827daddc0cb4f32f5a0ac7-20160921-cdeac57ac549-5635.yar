rule _20160921_b04df6930d827daddc0cb4f32f5a0ac7_20160921_cdeac57ac549_5635 {
  meta:
    description = "datamaliciousorder - from files 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js, 20160921_cdeac57ac549120611856c7af0c490f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"
    hash2       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"

  strings:
    $s1 = "f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg" ascii
    $s2 = "(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){r" ascii
    $s3 = " f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj" ascii
    $s4 = "00(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";}" ascii
    $s5 = "f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"T" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}