rule TTP_XOR_QUAD_CurrentVersionRun_e7c8 {
  strings:
    $key_e7c8 = { b4 a7 [2] 90 a9 [2] bb 85 [2] 95 a7 [2] 81 bc [2] 8e a6 [2] 90 bb [2] 92 ba [2] 89 bc [2] 95 bb [2] 89 94 }

  condition:
    any of them
}