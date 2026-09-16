rule TTP_XOR_QUAD_CurrentVersionRun_17c8 {
  strings:
    $key_17c8 = { 44 a7 [2] 60 a9 [2] 4b 85 [2] 65 a7 [2] 71 bc [2] 7e a6 [2] 60 bb [2] 62 ba [2] 79 bc [2] 65 bb [2] 79 94 }

  condition:
    any of them
}