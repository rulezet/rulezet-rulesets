rule TTP_XOR_QUAD_CurrentVersionRun_46c8 {
  strings:
    $key_46c8 = { 15 a7 [2] 31 a9 [2] 1a 85 [2] 34 a7 [2] 20 bc [2] 2f a6 [2] 31 bb [2] 33 ba [2] 28 bc [2] 34 bb [2] 28 94 }

  condition:
    any of them
}