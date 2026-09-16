rule TTP_XOR_QUAD_CurrentVersionRun_6543 {
  strings:
    $key_6543 = { 36 2c [2] 12 22 [2] 39 0e [2] 17 2c [2] 03 37 [2] 0c 2d [2] 12 30 [2] 10 31 [2] 0b 37 [2] 17 30 [2] 0b 1f }

  condition:
    any of them
}