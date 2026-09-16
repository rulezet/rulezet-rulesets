rule TTP_XOR_QUAD_CurrentVersionRun_3b43 {
  strings:
    $key_3b43 = { 68 2c [2] 4c 22 [2] 67 0e [2] 49 2c [2] 5d 37 [2] 52 2d [2] 4c 30 [2] 4e 31 [2] 55 37 [2] 49 30 [2] 55 1f }

  condition:
    any of them
}