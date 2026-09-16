rule TTP_XOR_QUAD_CurrentVersionRun_77c9 {
  strings:
    $key_77c9 = { 24 a6 [2] 00 a8 [2] 2b 84 [2] 05 a6 [2] 11 bd [2] 1e a7 [2] 00 ba [2] 02 bb [2] 19 bd [2] 05 ba [2] 19 95 }

  condition:
    any of them
}