rule TTP_XOR_QUAD_CurrentVersionRun_df6d {
  strings:
    $key_df6d = { 8c 02 [2] a8 0c [2] 83 20 [2] ad 02 [2] b9 19 [2] b6 03 [2] a8 1e [2] aa 1f [2] b1 19 [2] ad 1e [2] b1 31 }

  condition:
    any of them
}