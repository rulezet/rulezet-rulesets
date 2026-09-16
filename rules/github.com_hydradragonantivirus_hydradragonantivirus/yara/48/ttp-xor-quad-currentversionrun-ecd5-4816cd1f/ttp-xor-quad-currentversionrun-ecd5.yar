rule TTP_XOR_QUAD_CurrentVersionRun_ecd5 {
  strings:
    $key_ecd5 = { bf ba [2] 9b b4 [2] b0 98 [2] 9e ba [2] 8a a1 [2] 85 bb [2] 9b a6 [2] 99 a7 [2] 82 a1 [2] 9e a6 [2] 82 89 }

  condition:
    any of them
}