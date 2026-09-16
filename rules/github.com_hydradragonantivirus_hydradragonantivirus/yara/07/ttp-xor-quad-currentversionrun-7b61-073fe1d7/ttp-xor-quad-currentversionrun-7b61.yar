rule TTP_XOR_QUAD_CurrentVersionRun_7b61 {
  strings:
    $key_7b61 = { 28 0e [2] 0c 00 [2] 27 2c [2] 09 0e [2] 1d 15 [2] 12 0f [2] 0c 12 [2] 0e 13 [2] 15 15 [2] 09 12 [2] 15 3d }

  condition:
    any of them
}