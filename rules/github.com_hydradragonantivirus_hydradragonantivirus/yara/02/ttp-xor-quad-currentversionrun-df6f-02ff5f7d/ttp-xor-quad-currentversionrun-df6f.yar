rule TTP_XOR_QUAD_CurrentVersionRun_df6f {
  strings:
    $key_df6f = { 8c 00 [2] a8 0e [2] 83 22 [2] ad 00 [2] b9 1b [2] b6 01 [2] a8 1c [2] aa 1d [2] b1 1b [2] ad 1c [2] b1 33 }

  condition:
    any of them
}