rule TTP_XOR_QUAD_CurrentVersionRun_5443 {
  strings:
    $key_5443 = { 07 2c [2] 23 22 [2] 08 0e [2] 26 2c [2] 32 37 [2] 3d 2d [2] 23 30 [2] 21 31 [2] 3a 37 [2] 26 30 [2] 3a 1f }

  condition:
    any of them
}