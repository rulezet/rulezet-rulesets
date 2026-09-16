rule TTP_XOR_QUAD_CurrentVersionRun_4b61 {
  strings:
    $key_4b61 = { 18 0e [2] 3c 00 [2] 17 2c [2] 39 0e [2] 2d 15 [2] 22 0f [2] 3c 12 [2] 3e 13 [2] 25 15 [2] 39 12 [2] 25 3d }

  condition:
    any of them
}