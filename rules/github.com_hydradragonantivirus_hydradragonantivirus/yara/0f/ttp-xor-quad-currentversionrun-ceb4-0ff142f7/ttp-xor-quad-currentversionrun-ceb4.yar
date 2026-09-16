rule TTP_XOR_QUAD_CurrentVersionRun_ceb4 {
  strings:
    $key_ceb4 = { 9d db [2] b9 d5 [2] 92 f9 [2] bc db [2] a8 c0 [2] a7 da [2] b9 c7 [2] bb c6 [2] a0 c0 [2] bc c7 [2] a0 e8 }

  condition:
    any of them
}