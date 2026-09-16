rule TTP_XOR_QUAD_CurrentVersionRun_df51 {
  strings:
    $key_df51 = { 8c 3e [2] a8 30 [2] 83 1c [2] ad 3e [2] b9 25 [2] b6 3f [2] a8 22 [2] aa 23 [2] b1 25 [2] ad 22 [2] b1 0d }

  condition:
    any of them
}