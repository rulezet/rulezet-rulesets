rule TTP_XOR_QUAD_CurrentVersionRun_7a43 {
  strings:
    $key_7a43 = { 29 2c [2] 0d 22 [2] 26 0e [2] 08 2c [2] 1c 37 [2] 13 2d [2] 0d 30 [2] 0f 31 [2] 14 37 [2] 08 30 [2] 14 1f }

  condition:
    any of them
}