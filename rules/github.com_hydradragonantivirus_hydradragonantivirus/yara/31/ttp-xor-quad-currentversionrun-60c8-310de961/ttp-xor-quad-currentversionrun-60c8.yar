rule TTP_XOR_QUAD_CurrentVersionRun_60c8 {
  strings:
    $key_60c8 = { 33 a7 [2] 17 a9 [2] 3c 85 [2] 12 a7 [2] 06 bc [2] 09 a6 [2] 17 bb [2] 15 ba [2] 0e bc [2] 12 bb [2] 0e 94 }

  condition:
    any of them
}