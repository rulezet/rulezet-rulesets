rule TTP_XOR_QUAD_CurrentVersionRun_5643 {
  strings:
    $key_5643 = { 05 2c [2] 21 22 [2] 0a 0e [2] 24 2c [2] 30 37 [2] 3f 2d [2] 21 30 [2] 23 31 [2] 38 37 [2] 24 30 [2] 38 1f }

  condition:
    any of them
}