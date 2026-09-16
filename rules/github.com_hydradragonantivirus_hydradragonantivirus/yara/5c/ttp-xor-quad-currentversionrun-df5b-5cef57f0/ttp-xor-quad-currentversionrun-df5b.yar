rule TTP_XOR_QUAD_CurrentVersionRun_df5b {
  strings:
    $key_df5b = { 8c 34 [2] a8 3a [2] 83 16 [2] ad 34 [2] b9 2f [2] b6 35 [2] a8 28 [2] aa 29 [2] b1 2f [2] ad 28 [2] b1 07 }

  condition:
    any of them
}