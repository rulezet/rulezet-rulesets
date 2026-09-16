rule TTP_XOR_QUAD_CurrentVersionRun_4243 {
  strings:
    $key_4243 = { 11 2c [2] 35 22 [2] 1e 0e [2] 30 2c [2] 24 37 [2] 2b 2d [2] 35 30 [2] 37 31 [2] 2c 37 [2] 30 30 [2] 2c 1f }

  condition:
    any of them
}