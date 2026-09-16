rule TTP_XOR_QUAD_CurrentVersionRun_6043 {
  strings:
    $key_6043 = { 33 2c [2] 17 22 [2] 3c 0e [2] 12 2c [2] 06 37 [2] 09 2d [2] 17 30 [2] 15 31 [2] 0e 37 [2] 12 30 [2] 0e 1f }

  condition:
    any of them
}