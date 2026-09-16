rule TTP_XOR_QUAD_CurrentVersionRun_63d4 {
  strings:
    $key_63d4 = { 30 bb [2] 14 b5 [2] 3f 99 [2] 11 bb [2] 05 a0 [2] 0a ba [2] 14 a7 [2] 16 a6 [2] 0d a0 [2] 11 a7 [2] 0d 88 }

  condition:
    any of them
}