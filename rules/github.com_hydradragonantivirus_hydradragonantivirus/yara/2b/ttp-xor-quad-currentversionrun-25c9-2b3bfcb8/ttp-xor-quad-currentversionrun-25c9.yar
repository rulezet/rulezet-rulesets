rule TTP_XOR_QUAD_CurrentVersionRun_25c9 {
  strings:
    $key_25c9 = { 76 a6 [2] 52 a8 [2] 79 84 [2] 57 a6 [2] 43 bd [2] 4c a7 [2] 52 ba [2] 50 bb [2] 4b bd [2] 57 ba [2] 4b 95 }

  condition:
    any of them
}