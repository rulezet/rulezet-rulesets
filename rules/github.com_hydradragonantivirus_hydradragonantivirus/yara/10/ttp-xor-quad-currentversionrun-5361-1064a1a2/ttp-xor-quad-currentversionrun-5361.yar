rule TTP_XOR_QUAD_CurrentVersionRun_5361 {
  strings:
    $key_5361 = { 00 0e [2] 24 00 [2] 0f 2c [2] 21 0e [2] 35 15 [2] 3a 0f [2] 24 12 [2] 26 13 [2] 3d 15 [2] 21 12 [2] 3d 3d }

  condition:
    any of them
}