rule TTP_XOR_QUAD_CurrentVersionRun_27c9 {
  strings:
    $key_27c9 = { 74 a6 [2] 50 a8 [2] 7b 84 [2] 55 a6 [2] 41 bd [2] 4e a7 [2] 50 ba [2] 52 bb [2] 49 bd [2] 55 ba [2] 49 95 }

  condition:
    any of them
}