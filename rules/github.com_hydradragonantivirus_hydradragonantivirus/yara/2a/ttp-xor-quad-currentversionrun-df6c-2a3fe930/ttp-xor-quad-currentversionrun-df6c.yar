rule TTP_XOR_QUAD_CurrentVersionRun_df6c {
  strings:
    $key_df6c = { 8c 03 [2] a8 0d [2] 83 21 [2] ad 03 [2] b9 18 [2] b6 02 [2] a8 1f [2] aa 1e [2] b1 18 [2] ad 1f [2] b1 30 }

  condition:
    any of them
}