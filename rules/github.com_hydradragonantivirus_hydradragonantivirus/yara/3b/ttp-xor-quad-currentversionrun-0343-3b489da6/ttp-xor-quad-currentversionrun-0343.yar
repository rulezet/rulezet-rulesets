rule TTP_XOR_QUAD_CurrentVersionRun_0343 {
  strings:
    $key_0343 = { 50 2c [2] 74 22 [2] 5f 0e [2] 71 2c [2] 65 37 [2] 6a 2d [2] 74 30 [2] 76 31 [2] 6d 37 [2] 71 30 [2] 6d 1f }

  condition:
    any of them
}