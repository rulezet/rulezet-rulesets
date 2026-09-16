rule TTP_XOR_QUAD_CurrentVersionRun_ecb5 {
  strings:
    $key_ecb5 = { bf da [2] 9b d4 [2] b0 f8 [2] 9e da [2] 8a c1 [2] 85 db [2] 9b c6 [2] 99 c7 [2] 82 c1 [2] 9e c6 [2] 82 e9 }

  condition:
    any of them
}