rule TTP_XOR_QUAD_CurrentVersionRun_7442 {
  strings:
    $key_7442 = { 27 2d [2] 03 23 [2] 28 0f [2] 06 2d [2] 12 36 [2] 1d 2c [2] 03 31 [2] 01 30 [2] 1a 36 [2] 06 31 [2] 1a 1e }

  condition:
    any of them
}