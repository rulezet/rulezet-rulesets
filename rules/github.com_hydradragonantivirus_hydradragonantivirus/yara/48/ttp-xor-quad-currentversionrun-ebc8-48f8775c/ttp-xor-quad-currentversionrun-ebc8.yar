rule TTP_XOR_QUAD_CurrentVersionRun_ebc8 {
  strings:
    $key_ebc8 = { b8 a7 [2] 9c a9 [2] b7 85 [2] 99 a7 [2] 8d bc [2] 82 a6 [2] 9c bb [2] 9e ba [2] 85 bc [2] 99 bb [2] 85 94 }

  condition:
    any of them
}