rule TTP_XOR_QUAD_CurrentVersionRun_4377 {
  strings:
    $key_4377 = { 10 18 [2] 34 16 [2] 1f 3a [2] 31 18 [2] 25 03 [2] 2a 19 [2] 34 04 [2] 36 05 [2] 2d 03 [2] 31 04 [2] 2d 2b }

  condition:
    any of them
}