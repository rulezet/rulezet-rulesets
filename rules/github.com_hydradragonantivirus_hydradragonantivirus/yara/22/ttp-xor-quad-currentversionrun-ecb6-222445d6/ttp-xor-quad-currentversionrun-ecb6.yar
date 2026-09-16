rule TTP_XOR_QUAD_CurrentVersionRun_ecb6 {
  strings:
    $key_ecb6 = { bf d9 [2] 9b d7 [2] b0 fb [2] 9e d9 [2] 8a c2 [2] 85 d8 [2] 9b c5 [2] 99 c4 [2] 82 c2 [2] 9e c5 [2] 82 ea }

  condition:
    any of them
}