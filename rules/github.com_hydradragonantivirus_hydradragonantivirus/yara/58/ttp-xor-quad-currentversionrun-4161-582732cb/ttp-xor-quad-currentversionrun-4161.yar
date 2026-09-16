rule TTP_XOR_QUAD_CurrentVersionRun_4161 {
  strings:
    $key_4161 = { 12 0e [2] 36 00 [2] 1d 2c [2] 33 0e [2] 27 15 [2] 28 0f [2] 36 12 [2] 34 13 [2] 2f 15 [2] 33 12 [2] 2f 3d }

  condition:
    any of them
}