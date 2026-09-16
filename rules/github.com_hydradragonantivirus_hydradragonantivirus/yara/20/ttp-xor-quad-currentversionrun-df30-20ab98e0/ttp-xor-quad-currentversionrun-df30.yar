rule TTP_XOR_QUAD_CurrentVersionRun_df30 {
  strings:
    $key_df30 = { 8c 5f [2] a8 51 [2] 83 7d [2] ad 5f [2] b9 44 [2] b6 5e [2] a8 43 [2] aa 42 [2] b1 44 [2] ad 43 [2] b1 6c }

  condition:
    any of them
}