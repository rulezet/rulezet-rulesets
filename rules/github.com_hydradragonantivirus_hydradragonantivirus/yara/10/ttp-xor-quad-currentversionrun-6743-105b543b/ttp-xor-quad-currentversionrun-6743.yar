rule TTP_XOR_QUAD_CurrentVersionRun_6743 {
  strings:
    $key_6743 = { 34 2c [2] 10 22 [2] 3b 0e [2] 15 2c [2] 01 37 [2] 0e 2d [2] 10 30 [2] 12 31 [2] 09 37 [2] 15 30 [2] 09 1f }

  condition:
    any of them
}