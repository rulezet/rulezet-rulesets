rule TTP_XOR_QUAD_CurrentVersionRun_ecb4 {
  strings:
    $key_ecb4 = { bf db [2] 9b d5 [2] b0 f9 [2] 9e db [2] 8a c0 [2] 85 da [2] 9b c7 [2] 99 c6 [2] 82 c0 [2] 9e c7 [2] 82 e8 }

  condition:
    any of them
}