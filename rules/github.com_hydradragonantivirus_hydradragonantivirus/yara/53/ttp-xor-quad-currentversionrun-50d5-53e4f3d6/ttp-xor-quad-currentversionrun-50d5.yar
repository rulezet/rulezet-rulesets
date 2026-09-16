rule TTP_XOR_QUAD_CurrentVersionRun_50d5 {
  strings:
    $key_50d5 = { 03 ba [2] 27 b4 [2] 0c 98 [2] 22 ba [2] 36 a1 [2] 39 bb [2] 27 a6 [2] 25 a7 [2] 3e a1 [2] 22 a6 [2] 3e 89 }

  condition:
    any of them
}