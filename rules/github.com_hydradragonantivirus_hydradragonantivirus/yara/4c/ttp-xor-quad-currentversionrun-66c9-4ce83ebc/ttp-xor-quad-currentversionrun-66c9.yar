rule TTP_XOR_QUAD_CurrentVersionRun_66c9 {
  strings:
    $key_66c9 = { 35 a6 [2] 11 a8 [2] 3a 84 [2] 14 a6 [2] 00 bd [2] 0f a7 [2] 11 ba [2] 13 bb [2] 08 bd [2] 14 ba [2] 08 95 }

  condition:
    any of them
}