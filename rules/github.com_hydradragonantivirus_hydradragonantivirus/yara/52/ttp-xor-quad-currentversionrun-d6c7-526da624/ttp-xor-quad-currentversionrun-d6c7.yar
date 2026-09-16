rule TTP_XOR_QUAD_CurrentVersionRun_d6c7 {
  strings:
    $key_d6c7 = { 85 a8 [2] a1 a6 [2] 8a 8a [2] a4 a8 [2] b0 b3 [2] bf a9 [2] a1 b4 [2] a3 b5 [2] b8 b3 [2] a4 b4 [2] b8 9b }

  condition:
    any of them
}