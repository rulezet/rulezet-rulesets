rule TTP_XOR_QUAD_CurrentVersionRun_0bd4 {
  strings:
    $key_0bd4 = { 58 bb [2] 7c b5 [2] 57 99 [2] 79 bb [2] 6d a0 [2] 62 ba [2] 7c a7 [2] 7e a6 [2] 65 a0 [2] 79 a7 [2] 65 88 }

  condition:
    any of them
}