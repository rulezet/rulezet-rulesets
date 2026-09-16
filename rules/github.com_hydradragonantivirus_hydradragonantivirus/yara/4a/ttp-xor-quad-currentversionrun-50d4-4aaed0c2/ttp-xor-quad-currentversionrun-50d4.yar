rule TTP_XOR_QUAD_CurrentVersionRun_50d4 {
  strings:
    $key_50d4 = { 03 bb [2] 27 b5 [2] 0c 99 [2] 22 bb [2] 36 a0 [2] 39 ba [2] 27 a7 [2] 25 a6 [2] 3e a0 [2] 22 a7 [2] 3e 88 }

  condition:
    any of them
}