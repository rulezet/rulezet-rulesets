rule TTP_XOR_QUAD_CurrentVersionRun_7ec8 {
  strings:
    $key_7ec8 = { 2d a7 [2] 09 a9 [2] 22 85 [2] 0c a7 [2] 18 bc [2] 17 a6 [2] 09 bb [2] 0b ba [2] 10 bc [2] 0c bb [2] 10 94 }

  condition:
    any of them
}