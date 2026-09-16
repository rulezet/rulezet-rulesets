rule TTP_XOR_QUAD_CurrentVersionRun_4bd4 {
  strings:
    $key_4bd4 = { 18 bb [2] 3c b5 [2] 17 99 [2] 39 bb [2] 2d a0 [2] 22 ba [2] 3c a7 [2] 3e a6 [2] 25 a0 [2] 39 a7 [2] 25 88 }

  condition:
    any of them
}