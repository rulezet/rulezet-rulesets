rule TTP_XOR_QUAD_CurrentVersionRun_df61 {
  strings:
    $key_df61 = { 8c 0e [2] a8 00 [2] 83 2c [2] ad 0e [2] b9 15 [2] b6 0f [2] a8 12 [2] aa 13 [2] b1 15 [2] ad 12 [2] b1 3d }

  condition:
    any of them
}