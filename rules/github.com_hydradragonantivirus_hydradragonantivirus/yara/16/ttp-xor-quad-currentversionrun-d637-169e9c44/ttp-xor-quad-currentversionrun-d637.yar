rule TTP_XOR_QUAD_CurrentVersionRun_d637 {
  strings:
    $key_d637 = { 85 58 [2] a1 56 [2] 8a 7a [2] a4 58 [2] b0 43 [2] bf 59 [2] a1 44 [2] a3 45 [2] b8 43 [2] a4 44 [2] b8 6b }

  condition:
    any of them
}