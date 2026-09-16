rule TTP_XOR_QUAD_CurrentVersionRun_1e43 {
  strings:
    $key_1e43 = { 4d 2c [2] 69 22 [2] 42 0e [2] 6c 2c [2] 78 37 [2] 77 2d [2] 69 30 [2] 6b 31 [2] 70 37 [2] 6c 30 [2] 70 1f }

  condition:
    any of them
}