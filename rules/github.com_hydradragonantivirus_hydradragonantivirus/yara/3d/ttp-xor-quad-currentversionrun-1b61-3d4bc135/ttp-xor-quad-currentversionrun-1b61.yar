rule TTP_XOR_QUAD_CurrentVersionRun_1b61 {
  strings:
    $key_1b61 = { 48 0e [2] 6c 00 [2] 47 2c [2] 69 0e [2] 7d 15 [2] 72 0f [2] 6c 12 [2] 6e 13 [2] 75 15 [2] 69 12 [2] 75 3d }

  condition:
    any of them
}