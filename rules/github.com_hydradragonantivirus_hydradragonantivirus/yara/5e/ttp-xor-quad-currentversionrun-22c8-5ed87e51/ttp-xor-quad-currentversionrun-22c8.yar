rule TTP_XOR_QUAD_CurrentVersionRun_22c8 {
  strings:
    $key_22c8 = { 71 a7 [2] 55 a9 [2] 7e 85 [2] 50 a7 [2] 44 bc [2] 4b a6 [2] 55 bb [2] 57 ba [2] 4c bc [2] 50 bb [2] 4c 94 }

  condition:
    any of them
}