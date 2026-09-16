rule TTP_XOR_QUAD_CurrentVersionRun_df9c {
  strings:
    $key_df9c = { 8c f3 [2] a8 fd [2] 83 d1 [2] ad f3 [2] b9 e8 [2] b6 f2 [2] a8 ef [2] aa ee [2] b1 e8 [2] ad ef [2] b1 c0 }

  condition:
    any of them
}