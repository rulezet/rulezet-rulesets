rule TTP_XOR_QUAD_CurrentVersionRun_4361 {
  strings:
    $key_4361 = { 10 0e [2] 34 00 [2] 1f 2c [2] 31 0e [2] 25 15 [2] 2a 0f [2] 34 12 [2] 36 13 [2] 2d 15 [2] 31 12 [2] 2d 3d }

  condition:
    any of them
}