rule TTP_XOR_QUAD_CurrentVersionRun_2a43 {
  strings:
    $key_2a43 = { 79 2c [2] 5d 22 [2] 76 0e [2] 58 2c [2] 4c 37 [2] 43 2d [2] 5d 30 [2] 5f 31 [2] 44 37 [2] 58 30 [2] 44 1f }

  condition:
    any of them
}