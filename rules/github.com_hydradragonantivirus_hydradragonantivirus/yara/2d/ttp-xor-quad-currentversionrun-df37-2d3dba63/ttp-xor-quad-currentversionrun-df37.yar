rule TTP_XOR_QUAD_CurrentVersionRun_df37 {
  strings:
    $key_df37 = { 8c 58 [2] a8 56 [2] 83 7a [2] ad 58 [2] b9 43 [2] b6 59 [2] a8 44 [2] aa 45 [2] b1 43 [2] ad 44 [2] b1 6b }

  condition:
    any of them
}