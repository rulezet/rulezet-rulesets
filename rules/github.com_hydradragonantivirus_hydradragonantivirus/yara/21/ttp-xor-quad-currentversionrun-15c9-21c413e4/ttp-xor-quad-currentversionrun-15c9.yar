rule TTP_XOR_QUAD_CurrentVersionRun_15c9 {
  strings:
    $key_15c9 = { 46 a6 [2] 62 a8 [2] 49 84 [2] 67 a6 [2] 73 bd [2] 7c a7 [2] 62 ba [2] 60 bb [2] 7b bd [2] 67 ba [2] 7b 95 }

  condition:
    any of them
}