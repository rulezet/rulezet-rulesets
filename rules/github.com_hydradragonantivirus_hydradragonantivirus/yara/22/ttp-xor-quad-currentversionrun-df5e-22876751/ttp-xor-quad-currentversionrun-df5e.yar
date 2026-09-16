rule TTP_XOR_QUAD_CurrentVersionRun_df5e {
  strings:
    $key_df5e = { 8c 31 [2] a8 3f [2] 83 13 [2] ad 31 [2] b9 2a [2] b6 30 [2] a8 2d [2] aa 2c [2] b1 2a [2] ad 2d [2] b1 02 }

  condition:
    any of them
}