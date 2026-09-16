rule TTP_XOR_QUAD_CurrentVersionRun_6343 {
  strings:
    $key_6343 = { 30 2c [2] 14 22 [2] 3f 0e [2] 11 2c [2] 05 37 [2] 0a 2d [2] 14 30 [2] 16 31 [2] 0d 37 [2] 11 30 [2] 0d 1f }

  condition:
    any of them
}