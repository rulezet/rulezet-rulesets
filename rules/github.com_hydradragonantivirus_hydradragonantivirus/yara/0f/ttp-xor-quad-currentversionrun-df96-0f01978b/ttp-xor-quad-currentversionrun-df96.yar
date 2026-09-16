rule TTP_XOR_QUAD_CurrentVersionRun_df96 {
  strings:
    $key_df96 = { 8c f9 [2] a8 f7 [2] 83 db [2] ad f9 [2] b9 e2 [2] b6 f8 [2] a8 e5 [2] aa e4 [2] b1 e2 [2] ad e5 [2] b1 ca }

  condition:
    any of them
}