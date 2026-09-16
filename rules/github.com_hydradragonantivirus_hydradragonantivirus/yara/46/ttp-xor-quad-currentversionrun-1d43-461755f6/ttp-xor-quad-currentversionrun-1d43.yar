rule TTP_XOR_QUAD_CurrentVersionRun_1d43 {
  strings:
    $key_1d43 = { 4e 2c [2] 6a 22 [2] 41 0e [2] 6f 2c [2] 7b 37 [2] 74 2d [2] 6a 30 [2] 68 31 [2] 73 37 [2] 6f 30 [2] 73 1f }

  condition:
    any of them
}