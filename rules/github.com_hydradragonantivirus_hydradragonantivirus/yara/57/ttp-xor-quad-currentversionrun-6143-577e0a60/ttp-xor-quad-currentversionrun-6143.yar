rule TTP_XOR_QUAD_CurrentVersionRun_6143 {
  strings:
    $key_6143 = { 32 2c [2] 16 22 [2] 3d 0e [2] 13 2c [2] 07 37 [2] 08 2d [2] 16 30 [2] 14 31 [2] 0f 37 [2] 13 30 [2] 0f 1f }

  condition:
    any of them
}