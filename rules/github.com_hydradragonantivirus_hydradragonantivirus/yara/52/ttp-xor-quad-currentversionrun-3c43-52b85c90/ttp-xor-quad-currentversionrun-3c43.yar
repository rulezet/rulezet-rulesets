rule TTP_XOR_QUAD_CurrentVersionRun_3c43 {
  strings:
    $key_3c43 = { 6f 2c [2] 4b 22 [2] 60 0e [2] 4e 2c [2] 5a 37 [2] 55 2d [2] 4b 30 [2] 49 31 [2] 52 37 [2] 4e 30 [2] 52 1f }

  condition:
    any of them
}