rule TTP_XOR_QUAD_CurrentVersionRun_d2a6 {
  strings:
    $key_d2a6 = { 81 c9 [2] a5 c7 [2] 8e eb [2] a0 c9 [2] b4 d2 [2] bb c8 [2] a5 d5 [2] a7 d4 [2] bc d2 [2] a0 d5 [2] bc fa }

  condition:
    any of them
}