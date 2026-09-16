rule TTP_XOR_QUAD_CurrentVersionRun_df9d {
  strings:
    $key_df9d = { 8c f2 [2] a8 fc [2] 83 d0 [2] ad f2 [2] b9 e9 [2] b6 f3 [2] a8 ee [2] aa ef [2] b1 e9 [2] ad ee [2] b1 c1 }

  condition:
    any of them
}