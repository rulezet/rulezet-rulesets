rule TTP_XOR_QUAD_CurrentVersionRun_df71 {
  strings:
    $key_df71 = { 8c 1e [2] a8 10 [2] 83 3c [2] ad 1e [2] b9 05 [2] b6 1f [2] a8 02 [2] aa 03 [2] b1 05 [2] ad 02 [2] b1 2d }

  condition:
    any of them
}