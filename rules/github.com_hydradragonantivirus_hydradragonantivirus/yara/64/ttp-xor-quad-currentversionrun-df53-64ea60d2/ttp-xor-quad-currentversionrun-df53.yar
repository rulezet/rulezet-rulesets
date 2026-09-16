rule TTP_XOR_QUAD_CurrentVersionRun_df53 {
  strings:
    $key_df53 = { 8c 3c [2] a8 32 [2] 83 1e [2] ad 3c [2] b9 27 [2] b6 3d [2] a8 20 [2] aa 21 [2] b1 27 [2] ad 20 [2] b1 0f }

  condition:
    any of them
}