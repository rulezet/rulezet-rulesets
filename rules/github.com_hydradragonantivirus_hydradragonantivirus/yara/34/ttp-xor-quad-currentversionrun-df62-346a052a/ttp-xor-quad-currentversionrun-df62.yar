rule TTP_XOR_QUAD_CurrentVersionRun_df62 {
  strings:
    $key_df62 = { 8c 0d [2] a8 03 [2] 83 2f [2] ad 0d [2] b9 16 [2] b6 0c [2] a8 11 [2] aa 10 [2] b1 16 [2] ad 11 [2] b1 3e }

  condition:
    any of them
}