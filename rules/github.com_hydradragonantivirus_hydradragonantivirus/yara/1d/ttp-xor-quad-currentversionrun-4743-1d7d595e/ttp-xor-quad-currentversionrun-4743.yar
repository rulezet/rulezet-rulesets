rule TTP_XOR_QUAD_CurrentVersionRun_4743 {
  strings:
    $key_4743 = { 14 2c [2] 30 22 [2] 1b 0e [2] 35 2c [2] 21 37 [2] 2e 2d [2] 30 30 [2] 32 31 [2] 29 37 [2] 35 30 [2] 29 1f }

  condition:
    any of them
}