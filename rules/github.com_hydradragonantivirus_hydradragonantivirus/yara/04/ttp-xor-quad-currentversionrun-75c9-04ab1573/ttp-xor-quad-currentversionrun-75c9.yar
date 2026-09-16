rule TTP_XOR_QUAD_CurrentVersionRun_75c9 {
  strings:
    $key_75c9 = { 26 a6 [2] 02 a8 [2] 29 84 [2] 07 a6 [2] 13 bd [2] 1c a7 [2] 02 ba [2] 00 bb [2] 1b bd [2] 07 ba [2] 1b 95 }

  condition:
    any of them
}