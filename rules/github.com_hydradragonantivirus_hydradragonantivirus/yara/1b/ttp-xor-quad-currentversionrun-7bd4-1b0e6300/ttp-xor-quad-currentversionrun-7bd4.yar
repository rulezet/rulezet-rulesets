rule TTP_XOR_QUAD_CurrentVersionRun_7bd4 {
  strings:
    $key_7bd4 = { 28 bb [2] 0c b5 [2] 27 99 [2] 09 bb [2] 1d a0 [2] 12 ba [2] 0c a7 [2] 0e a6 [2] 15 a0 [2] 09 a7 [2] 15 88 }

  condition:
    any of them
}