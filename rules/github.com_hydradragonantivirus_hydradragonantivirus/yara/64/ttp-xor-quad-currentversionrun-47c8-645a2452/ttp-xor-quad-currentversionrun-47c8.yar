rule TTP_XOR_QUAD_CurrentVersionRun_47c8 {
  strings:
    $key_47c8 = { 14 a7 [2] 30 a9 [2] 1b 85 [2] 35 a7 [2] 21 bc [2] 2e a6 [2] 30 bb [2] 32 ba [2] 29 bc [2] 35 bb [2] 29 94 }

  condition:
    any of them
}