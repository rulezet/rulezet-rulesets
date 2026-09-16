rule TTP_XOR_QUAD_CurrentVersionRun_4461 {
  strings:
    $key_4461 = { 17 0e [2] 33 00 [2] 18 2c [2] 36 0e [2] 22 15 [2] 2d 0f [2] 33 12 [2] 31 13 [2] 2a 15 [2] 36 12 [2] 2a 3d }

  condition:
    any of them
}