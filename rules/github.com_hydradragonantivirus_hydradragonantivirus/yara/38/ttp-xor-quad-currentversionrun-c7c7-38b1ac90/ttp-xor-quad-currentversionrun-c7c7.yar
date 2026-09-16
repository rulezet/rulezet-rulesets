rule TTP_XOR_QUAD_CurrentVersionRun_c7c7 {
  strings:
    $key_c7c7 = { 94 a8 [2] b0 a6 [2] 9b 8a [2] b5 a8 [2] a1 b3 [2] ae a9 [2] b0 b4 [2] b2 b5 [2] a9 b3 [2] b5 b4 [2] a9 9b }

  condition:
    any of them
}