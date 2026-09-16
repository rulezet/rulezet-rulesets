rule TTP_XOR_QUAD_CurrentVersionRun_5243 {
  strings:
    $key_5243 = { 01 2c [2] 25 22 [2] 0e 0e [2] 20 2c [2] 34 37 [2] 3b 2d [2] 25 30 [2] 27 31 [2] 3c 37 [2] 20 30 [2] 3c 1f }

  condition:
    any of them
}