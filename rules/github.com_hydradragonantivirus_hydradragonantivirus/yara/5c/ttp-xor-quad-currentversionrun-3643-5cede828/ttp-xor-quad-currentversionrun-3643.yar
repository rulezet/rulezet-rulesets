rule TTP_XOR_QUAD_CurrentVersionRun_3643 {
  strings:
    $key_3643 = { 65 2c [2] 41 22 [2] 6a 0e [2] 44 2c [2] 50 37 [2] 5f 2d [2] 41 30 [2] 43 31 [2] 58 37 [2] 44 30 [2] 58 1f }

  condition:
    any of them
}