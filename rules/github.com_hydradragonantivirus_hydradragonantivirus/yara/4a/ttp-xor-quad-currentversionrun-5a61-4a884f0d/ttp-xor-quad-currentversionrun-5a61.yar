rule TTP_XOR_QUAD_CurrentVersionRun_5a61 {
  strings:
    $key_5a61 = { 09 0e [2] 2d 00 [2] 06 2c [2] 28 0e [2] 3c 15 [2] 33 0f [2] 2d 12 [2] 2f 13 [2] 34 15 [2] 28 12 [2] 34 3d }

  condition:
    any of them
}