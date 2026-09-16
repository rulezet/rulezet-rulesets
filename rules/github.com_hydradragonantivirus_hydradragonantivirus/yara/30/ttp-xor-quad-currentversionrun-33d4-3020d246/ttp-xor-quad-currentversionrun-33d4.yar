rule TTP_XOR_QUAD_CurrentVersionRun_33d4 {
  strings:
    $key_33d4 = { 60 bb [2] 44 b5 [2] 6f 99 [2] 41 bb [2] 55 a0 [2] 5a ba [2] 44 a7 [2] 46 a6 [2] 5d a0 [2] 41 a7 [2] 5d 88 }

  condition:
    any of them
}