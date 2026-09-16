rule TTP_XOR_QUAD_CurrentVersionRun_c685 {
  strings:
    $key_c685 = { 95 ea [2] b1 e4 [2] 9a c8 [2] b4 ea [2] a0 f1 [2] af eb [2] b1 f6 [2] b3 f7 [2] a8 f1 [2] b4 f6 [2] a8 d9 }

  condition:
    any of them
}