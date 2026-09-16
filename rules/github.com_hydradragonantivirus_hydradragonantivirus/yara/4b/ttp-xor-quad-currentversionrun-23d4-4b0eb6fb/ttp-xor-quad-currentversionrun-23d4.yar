rule TTP_XOR_QUAD_CurrentVersionRun_23d4 {
  strings:
    $key_23d4 = { 70 bb [2] 54 b5 [2] 7f 99 [2] 51 bb [2] 45 a0 [2] 4a ba [2] 54 a7 [2] 56 a6 [2] 4d a0 [2] 51 a7 [2] 4d 88 }

  condition:
    any of them
}