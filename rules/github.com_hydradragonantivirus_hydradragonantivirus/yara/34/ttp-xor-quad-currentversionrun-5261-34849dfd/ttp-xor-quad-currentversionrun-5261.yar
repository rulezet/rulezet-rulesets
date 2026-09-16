rule TTP_XOR_QUAD_CurrentVersionRun_5261 {
  strings:
    $key_5261 = { 01 0e [2] 25 00 [2] 0e 2c [2] 20 0e [2] 34 15 [2] 3b 0f [2] 25 12 [2] 27 13 [2] 3c 15 [2] 20 12 [2] 3c 3d }

  condition:
    any of them
}