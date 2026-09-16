rule TTP_XOR_QUAD_CurrentVersionRun_df31 {
  strings:
    $key_df31 = { 8c 5e [2] a8 50 [2] 83 7c [2] ad 5e [2] b9 45 [2] b6 5f [2] a8 42 [2] aa 43 [2] b1 45 [2] ad 42 [2] b1 6d }

  condition:
    any of them
}