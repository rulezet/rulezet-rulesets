rule TTP_XOR_QUAD_CurrentVersionRun_df03 {
  strings:
    $key_df03 = { 8c 6c [2] a8 62 [2] 83 4e [2] ad 6c [2] b9 77 [2] b6 6d [2] a8 70 [2] aa 71 [2] b1 77 [2] ad 70 [2] b1 5f }

  condition:
    any of them
}