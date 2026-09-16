rule TTP_XOR_QUAD_CurrentVersionRun_df01 {
  strings:
    $key_df01 = { 8c 6e [2] a8 60 [2] 83 4c [2] ad 6e [2] b9 75 [2] b6 6f [2] a8 72 [2] aa 73 [2] b1 75 [2] ad 72 [2] b1 5d }

  condition:
    any of them
}