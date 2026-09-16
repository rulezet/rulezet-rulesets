rule TTP_XOR_QUAD_CurrentVersionRun_dfc8 {
  strings:
    $key_dfc8 = { 8c a7 [2] a8 a9 [2] 83 85 [2] ad a7 [2] b9 bc [2] b6 a6 [2] a8 bb [2] aa ba [2] b1 bc [2] ad bb [2] b1 94 }

  condition:
    any of them
}