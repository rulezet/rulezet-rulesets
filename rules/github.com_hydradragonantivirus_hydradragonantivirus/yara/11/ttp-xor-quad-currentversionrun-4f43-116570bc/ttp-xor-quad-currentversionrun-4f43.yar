rule TTP_XOR_QUAD_CurrentVersionRun_4f43 {
  strings:
    $key_4f43 = { 1c 2c [2] 38 22 [2] 13 0e [2] 3d 2c [2] 29 37 [2] 26 2d [2] 38 30 [2] 3a 31 [2] 21 37 [2] 3d 30 [2] 21 1f }

  condition:
    any of them
}