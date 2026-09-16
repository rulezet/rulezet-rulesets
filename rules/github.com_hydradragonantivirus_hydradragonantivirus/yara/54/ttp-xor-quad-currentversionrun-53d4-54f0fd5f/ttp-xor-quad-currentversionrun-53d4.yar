rule TTP_XOR_QUAD_CurrentVersionRun_53d4 {
  strings:
    $key_53d4 = { 00 bb [2] 24 b5 [2] 0f 99 [2] 21 bb [2] 35 a0 [2] 3a ba [2] 24 a7 [2] 26 a6 [2] 3d a0 [2] 21 a7 [2] 3d 88 }

  condition:
    any of them
}