rule TTP_XOR_QUAD_CurrentVersionRun_1743 {
  strings:
    $key_1743 = { 44 2c [2] 60 22 [2] 4b 0e [2] 65 2c [2] 71 37 [2] 7e 2d [2] 60 30 [2] 62 31 [2] 79 37 [2] 65 30 [2] 79 1f }

  condition:
    any of them
}