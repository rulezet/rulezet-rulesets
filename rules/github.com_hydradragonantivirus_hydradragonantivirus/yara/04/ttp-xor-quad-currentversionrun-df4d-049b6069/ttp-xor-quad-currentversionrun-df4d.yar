rule TTP_XOR_QUAD_CurrentVersionRun_df4d {
  strings:
    $key_df4d = { 8c 22 [2] a8 2c [2] 83 00 [2] ad 22 [2] b9 39 [2] b6 23 [2] a8 3e [2] aa 3f [2] b1 39 [2] ad 3e [2] b1 11 }

  condition:
    any of them
}