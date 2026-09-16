rule TTP_XOR_QUAD_CurrentVersionRun_d5da {
  strings:
    $key_d5da = { 86 b5 [2] a2 bb [2] 89 97 [2] a7 b5 [2] b3 ae [2] bc b4 [2] a2 a9 [2] a0 a8 [2] bb ae [2] a7 a9 [2] bb 86 }

  condition:
    any of them
}