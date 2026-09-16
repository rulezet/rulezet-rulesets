rule TTP_XOR_QUAD_CurrentVersionRun_df70 {
  strings:
    $key_df70 = { 8c 1f [2] a8 11 [2] 83 3d [2] ad 1f [2] b9 04 [2] b6 1e [2] a8 03 [2] aa 02 [2] b1 04 [2] ad 03 [2] b1 2c }

  condition:
    any of them
}