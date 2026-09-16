rule TTP_XOR_QUAD_CurrentVersionRun_3543 {
  strings:
    $key_3543 = { 66 2c [2] 42 22 [2] 69 0e [2] 47 2c [2] 53 37 [2] 5c 2d [2] 42 30 [2] 40 31 [2] 5b 37 [2] 47 30 [2] 5b 1f }

  condition:
    any of them
}