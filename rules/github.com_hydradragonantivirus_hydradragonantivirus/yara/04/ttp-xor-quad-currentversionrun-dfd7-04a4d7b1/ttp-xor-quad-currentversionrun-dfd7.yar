rule TTP_XOR_QUAD_CurrentVersionRun_dfd7 {
  strings:
    $key_dfd7 = { 8c b8 [2] a8 b6 [2] 83 9a [2] ad b8 [2] b9 a3 [2] b6 b9 [2] a8 a4 [2] aa a5 [2] b1 a3 [2] ad a4 [2] b1 8b }

  condition:
    any of them
}