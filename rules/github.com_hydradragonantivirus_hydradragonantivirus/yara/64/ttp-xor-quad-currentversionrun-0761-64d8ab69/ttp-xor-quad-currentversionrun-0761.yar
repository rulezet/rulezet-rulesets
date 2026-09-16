rule TTP_XOR_QUAD_CurrentVersionRun_0761 {
  strings:
    $key_0761 = { 54 0e [2] 70 00 [2] 5b 2c [2] 75 0e [2] 61 15 [2] 6e 0f [2] 70 12 [2] 72 13 [2] 69 15 [2] 75 12 [2] 69 3d }

  condition:
    any of them
}