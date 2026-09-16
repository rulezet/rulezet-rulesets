rule TTP_XOR_QUAD_CurrentVersionRun_ecd4 {
  strings:
    $key_ecd4 = { bf bb [2] 9b b5 [2] b0 99 [2] 9e bb [2] 8a a0 [2] 85 ba [2] 9b a7 [2] 99 a6 [2] 82 a0 [2] 9e a7 [2] 82 88 }

  condition:
    any of them
}