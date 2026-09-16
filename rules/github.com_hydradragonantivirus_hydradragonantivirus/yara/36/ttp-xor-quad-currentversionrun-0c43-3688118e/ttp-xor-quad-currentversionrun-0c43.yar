rule TTP_XOR_QUAD_CurrentVersionRun_0c43 {
  strings:
    $key_0c43 = { 5f 2c [2] 7b 22 [2] 50 0e [2] 7e 2c [2] 6a 37 [2] 65 2d [2] 7b 30 [2] 79 31 [2] 62 37 [2] 7e 30 [2] 62 1f }

  condition:
    any of them
}