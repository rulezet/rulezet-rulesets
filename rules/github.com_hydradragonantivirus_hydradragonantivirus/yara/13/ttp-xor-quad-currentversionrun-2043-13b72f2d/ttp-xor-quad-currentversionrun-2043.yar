rule TTP_XOR_QUAD_CurrentVersionRun_2043 {
  strings:
    $key_2043 = { 73 2c [2] 57 22 [2] 7c 0e [2] 52 2c [2] 46 37 [2] 49 2d [2] 57 30 [2] 55 31 [2] 4e 37 [2] 52 30 [2] 4e 1f }

  condition:
    any of them
}