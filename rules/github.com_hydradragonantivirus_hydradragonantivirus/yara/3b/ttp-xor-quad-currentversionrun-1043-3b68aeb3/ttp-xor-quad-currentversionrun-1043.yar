rule TTP_XOR_QUAD_CurrentVersionRun_1043 {
  strings:
    $key_1043 = { 43 2c [2] 67 22 [2] 4c 0e [2] 62 2c [2] 76 37 [2] 79 2d [2] 67 30 [2] 65 31 [2] 7e 37 [2] 62 30 [2] 7e 1f }

  condition:
    any of them
}