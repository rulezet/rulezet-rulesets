rule TTP_XOR_QUAD_CurrentVersionRun_df4f {
  strings:
    $key_df4f = { 8c 20 [2] a8 2e [2] 83 02 [2] ad 20 [2] b9 3b [2] b6 21 [2] a8 3c [2] aa 3d [2] b1 3b [2] ad 3c [2] b1 13 }

  condition:
    any of them
}