rule TTP_XOR_QUAD_CurrentVersionRun_df58 {
  strings:
    $key_df58 = { 8c 37 [2] a8 39 [2] 83 15 [2] ad 37 [2] b9 2c [2] b6 36 [2] a8 2b [2] aa 2a [2] b1 2c [2] ad 2b [2] b1 04 }

  condition:
    any of them
}