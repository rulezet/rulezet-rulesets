rule TTP_XOR_QUAD_CurrentVersionRun_df00 {
  strings:
    $key_df00 = { 8c 6f [2] a8 61 [2] 83 4d [2] ad 6f [2] b9 74 [2] b6 6e [2] a8 73 [2] aa 72 [2] b1 74 [2] ad 73 [2] b1 5c }

  condition:
    any of them
}