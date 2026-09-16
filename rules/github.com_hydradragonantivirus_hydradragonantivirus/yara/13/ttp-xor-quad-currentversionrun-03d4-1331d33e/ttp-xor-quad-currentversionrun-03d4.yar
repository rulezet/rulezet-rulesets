rule TTP_XOR_QUAD_CurrentVersionRun_03d4 {
  strings:
    $key_03d4 = { 50 bb [2] 74 b5 [2] 5f 99 [2] 71 bb [2] 65 a0 [2] 6a ba [2] 74 a7 [2] 76 a6 [2] 6d a0 [2] 71 a7 [2] 6d 88 }

  condition:
    any of them
}