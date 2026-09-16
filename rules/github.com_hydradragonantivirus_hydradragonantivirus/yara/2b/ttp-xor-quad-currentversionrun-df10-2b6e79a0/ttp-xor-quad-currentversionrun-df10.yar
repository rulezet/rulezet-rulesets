rule TTP_XOR_QUAD_CurrentVersionRun_df10 {
  strings:
    $key_df10 = { 8c 7f [2] a8 71 [2] 83 5d [2] ad 7f [2] b9 64 [2] b6 7e [2] a8 63 [2] aa 62 [2] b1 64 [2] ad 63 [2] b1 4c }

  condition:
    any of them
}