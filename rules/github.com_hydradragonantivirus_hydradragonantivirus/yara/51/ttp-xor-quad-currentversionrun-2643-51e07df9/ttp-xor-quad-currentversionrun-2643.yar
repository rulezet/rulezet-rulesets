rule TTP_XOR_QUAD_CurrentVersionRun_2643 {
  strings:
    $key_2643 = { 75 2c [2] 51 22 [2] 7a 0e [2] 54 2c [2] 40 37 [2] 4f 2d [2] 51 30 [2] 53 31 [2] 48 37 [2] 54 30 [2] 48 1f }

  condition:
    any of them
}