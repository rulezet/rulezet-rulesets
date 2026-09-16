rule TTP_XOR_QUAD_CurrentVersionRun_6bd4 {
  strings:
    $key_6bd4 = { 38 bb [2] 1c b5 [2] 37 99 [2] 19 bb [2] 0d a0 [2] 02 ba [2] 1c a7 [2] 1e a6 [2] 05 a0 [2] 19 a7 [2] 05 88 }

  condition:
    any of them
}