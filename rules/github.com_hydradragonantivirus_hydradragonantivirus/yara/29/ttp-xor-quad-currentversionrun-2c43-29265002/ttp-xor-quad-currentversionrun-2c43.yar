rule TTP_XOR_QUAD_CurrentVersionRun_2c43 {
  strings:
    $key_2c43 = { 7f 2c [2] 5b 22 [2] 70 0e [2] 5e 2c [2] 4a 37 [2] 45 2d [2] 5b 30 [2] 59 31 [2] 42 37 [2] 5e 30 [2] 42 1f }

  condition:
    any of them
}