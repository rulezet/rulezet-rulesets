rule TTP_XOR_QUAD_CurrentVersionRun_17c9 {
  strings:
    $key_17c9 = { 44 a6 [2] 60 a8 [2] 4b 84 [2] 65 a6 [2] 71 bd [2] 7e a7 [2] 60 ba [2] 62 bb [2] 79 bd [2] 65 ba [2] 79 95 }

  condition:
    any of them
}