rule TTP_XOR_QUAD_CurrentVersionRun_1143 {
  strings:
    $key_1143 = { 42 2c [2] 66 22 [2] 4d 0e [2] 63 2c [2] 77 37 [2] 78 2d [2] 66 30 [2] 64 31 [2] 7f 37 [2] 63 30 [2] 7f 1f }

  condition:
    any of them
}