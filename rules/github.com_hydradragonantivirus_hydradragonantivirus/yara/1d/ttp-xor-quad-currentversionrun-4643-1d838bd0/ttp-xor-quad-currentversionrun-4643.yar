rule TTP_XOR_QUAD_CurrentVersionRun_4643 {
  strings:
    $key_4643 = { 15 2c [2] 31 22 [2] 1a 0e [2] 34 2c [2] 20 37 [2] 2f 2d [2] 31 30 [2] 33 31 [2] 28 37 [2] 34 30 [2] 28 1f }

  condition:
    any of them
}