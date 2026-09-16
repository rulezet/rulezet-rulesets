rule TTP_XOR_QUAD_CurrentVersionRun_df4c {
  strings:
    $key_df4c = { 8c 23 [2] a8 2d [2] 83 01 [2] ad 23 [2] b9 38 [2] b6 22 [2] a8 3f [2] aa 3e [2] b1 38 [2] ad 3f [2] b1 10 }

  condition:
    any of them
}