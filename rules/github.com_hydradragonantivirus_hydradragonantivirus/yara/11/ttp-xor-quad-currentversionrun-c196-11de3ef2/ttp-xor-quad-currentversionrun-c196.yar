rule TTP_XOR_QUAD_CurrentVersionRun_c196 {
  strings:
    $key_c196 = { 92 f9 [2] b6 f7 [2] 9d db [2] b3 f9 [2] a7 e2 [2] a8 f8 [2] b6 e5 [2] b4 e4 [2] af e2 [2] b3 e5 [2] af ca }

  condition:
    any of them
}