rule TTP_XOR_QUAD_CurrentVersionRun_df06 {
  strings:
    $key_df06 = { 8c 69 [2] a8 67 [2] 83 4b [2] ad 69 [2] b9 72 [2] b6 68 [2] a8 75 [2] aa 74 [2] b1 72 [2] ad 75 [2] b1 5a }

  condition:
    any of them
}