rule TTP_XOR_QUAD_CurrentVersionRun_df02 {
  strings:
    $key_df02 = { 8c 6d [2] a8 63 [2] 83 4f [2] ad 6d [2] b9 76 [2] b6 6c [2] a8 71 [2] aa 70 [2] b1 76 [2] ad 71 [2] b1 5e }

  condition:
    any of them
}