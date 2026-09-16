rule TTP_XOR_QUAD_CurrentVersionRun_4343 {
  strings:
    $key_4343 = { 10 2c [2] 34 22 [2] 1f 0e [2] 31 2c [2] 25 37 [2] 2a 2d [2] 34 30 [2] 36 31 [2] 2d 37 [2] 31 30 [2] 2d 1f }

  condition:
    any of them
}