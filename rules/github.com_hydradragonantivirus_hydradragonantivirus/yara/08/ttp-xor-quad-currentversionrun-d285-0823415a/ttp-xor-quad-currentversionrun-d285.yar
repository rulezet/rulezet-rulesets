rule TTP_XOR_QUAD_CurrentVersionRun_d285 {
  strings:
    $key_d285 = { 81 ea [2] a5 e4 [2] 8e c8 [2] a0 ea [2] b4 f1 [2] bb eb [2] a5 f6 [2] a7 f7 [2] bc f1 [2] a0 f6 [2] bc d9 }

  condition:
    any of them
}