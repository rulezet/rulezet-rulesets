rule TTP_XOR_QUAD_CurrentVersionRun_65c9 {
  strings:
    $key_65c9 = { 36 a6 [2] 12 a8 [2] 39 84 [2] 17 a6 [2] 03 bd [2] 0c a7 [2] 12 ba [2] 10 bb [2] 0b bd [2] 17 ba [2] 0b 95 }

  condition:
    any of them
}