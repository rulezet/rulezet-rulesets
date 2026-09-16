rule TTP_XOR_QUAD_CurrentVersionRun_df36 {
  strings:
    $key_df36 = { 8c 59 [2] a8 57 [2] 83 7b [2] ad 59 [2] b9 42 [2] b6 58 [2] a8 45 [2] aa 44 [2] b1 42 [2] ad 45 [2] b1 6a }

  condition:
    any of them
}