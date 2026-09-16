rule TTP_XOR_QUAD_CurrentVersionRun_2d43 {
  strings:
    $key_2d43 = { 7e 2c [2] 5a 22 [2] 71 0e [2] 5f 2c [2] 4b 37 [2] 44 2d [2] 5a 30 [2] 58 31 [2] 43 37 [2] 5f 30 [2] 43 1f }

  condition:
    any of them
}