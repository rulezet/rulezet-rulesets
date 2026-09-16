rule TTP_XOR_QUAD_CurrentVersionRun_3ec8 {
  strings:
    $key_3ec8 = { 6d a7 [2] 49 a9 [2] 62 85 [2] 4c a7 [2] 58 bc [2] 57 a6 [2] 49 bb [2] 4b ba [2] 50 bc [2] 4c bb [2] 50 94 }

  condition:
    any of them
}