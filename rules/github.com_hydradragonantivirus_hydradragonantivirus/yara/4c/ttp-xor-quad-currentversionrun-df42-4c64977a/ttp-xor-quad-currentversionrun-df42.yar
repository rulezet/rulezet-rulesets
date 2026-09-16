rule TTP_XOR_QUAD_CurrentVersionRun_df42 {
  strings:
    $key_df42 = { 8c 2d [2] a8 23 [2] 83 0f [2] ad 2d [2] b9 36 [2] b6 2c [2] a8 31 [2] aa 30 [2] b1 36 [2] ad 31 [2] b1 1e }

  condition:
    any of them
}