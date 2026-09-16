rule TTP_XOR_QUAD_CurrentVersionRun_df2c {
  strings:
    $key_df2c = { 8c 43 [2] a8 4d [2] 83 61 [2] ad 43 [2] b9 58 [2] b6 42 [2] a8 5f [2] aa 5e [2] b1 58 [2] ad 5f [2] b1 70 }

  condition:
    any of them
}