rule TTP_XOR_QUAD_CurrentVersionRun_fcd4 {
  strings:
    $key_fcd4 = { af bb [2] 8b b5 [2] a0 99 [2] 8e bb [2] 9a a0 [2] 95 ba [2] 8b a7 [2] 89 a6 [2] 92 a0 [2] 8e a7 [2] 92 88 }

  condition:
    any of them
}