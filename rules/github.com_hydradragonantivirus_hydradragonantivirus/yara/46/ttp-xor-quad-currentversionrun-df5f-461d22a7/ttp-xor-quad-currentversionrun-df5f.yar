rule TTP_XOR_QUAD_CurrentVersionRun_df5f {
  strings:
    $key_df5f = { 8c 30 [2] a8 3e [2] 83 12 [2] ad 30 [2] b9 2b [2] b6 31 [2] a8 2c [2] aa 2d [2] b1 2b [2] ad 2c [2] b1 03 }

  condition:
    any of them
}