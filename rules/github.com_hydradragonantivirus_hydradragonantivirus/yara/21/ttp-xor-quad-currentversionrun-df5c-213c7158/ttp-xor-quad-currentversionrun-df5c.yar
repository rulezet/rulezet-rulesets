rule TTP_XOR_QUAD_CurrentVersionRun_df5c {
  strings:
    $key_df5c = { 8c 33 [2] a8 3d [2] 83 11 [2] ad 33 [2] b9 28 [2] b6 32 [2] a8 2f [2] aa 2e [2] b1 28 [2] ad 2f [2] b1 00 }

  condition:
    any of them
}