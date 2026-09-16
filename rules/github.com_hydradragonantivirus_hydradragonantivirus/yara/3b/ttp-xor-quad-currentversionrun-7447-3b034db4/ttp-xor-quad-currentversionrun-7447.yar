rule TTP_XOR_QUAD_CurrentVersionRun_7447 {
  strings:
    $key_7447 = { 27 28 [2] 03 26 [2] 28 0a [2] 06 28 [2] 12 33 [2] 1d 29 [2] 03 34 [2] 01 35 [2] 1a 33 [2] 06 34 [2] 1a 1b }

  condition:
    any of them
}