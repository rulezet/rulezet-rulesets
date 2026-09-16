rule TTP_XOR_QUAD_CurrentVersionRun_df23 {
  strings:
    $key_df23 = { 8c 4c [2] a8 42 [2] 83 6e [2] ad 4c [2] b9 57 [2] b6 4d [2] a8 50 [2] aa 51 [2] b1 57 [2] ad 50 [2] b1 7f }

  condition:
    any of them
}