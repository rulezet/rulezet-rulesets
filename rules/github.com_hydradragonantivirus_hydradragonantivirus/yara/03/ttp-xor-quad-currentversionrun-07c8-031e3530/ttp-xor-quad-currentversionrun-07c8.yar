rule TTP_XOR_QUAD_CurrentVersionRun_07c8 {
  strings:
    $key_07c8 = { 54 a7 [2] 70 a9 [2] 5b 85 [2] 75 a7 [2] 61 bc [2] 6e a6 [2] 70 bb [2] 72 ba [2] 69 bc [2] 75 bb [2] 69 94 }

  condition:
    any of them
}