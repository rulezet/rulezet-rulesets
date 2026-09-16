rule TTP_XOR_QUAD_CurrentVersionRun_5561 {
  strings:
    $key_5561 = { 06 0e [2] 22 00 [2] 09 2c [2] 27 0e [2] 33 15 [2] 3c 0f [2] 22 12 [2] 20 13 [2] 3b 15 [2] 27 12 [2] 3b 3d }

  condition:
    any of them
}