rule TTP_XOR_QUAD_CurrentVersionRun_df33 {
  strings:
    $key_df33 = { 8c 5c [2] a8 52 [2] 83 7e [2] ad 5c [2] b9 47 [2] b6 5d [2] a8 40 [2] aa 41 [2] b1 47 [2] ad 40 [2] b1 6f }

  condition:
    any of them
}