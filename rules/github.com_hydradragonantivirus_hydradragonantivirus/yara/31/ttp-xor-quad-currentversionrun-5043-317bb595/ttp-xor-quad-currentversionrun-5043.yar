rule TTP_XOR_QUAD_CurrentVersionRun_5043 {
  strings:
    $key_5043 = { 03 2c [2] 27 22 [2] 0c 0e [2] 22 2c [2] 36 37 [2] 39 2d [2] 27 30 [2] 25 31 [2] 3e 37 [2] 22 30 [2] 3e 1f }

  condition:
    any of them
}