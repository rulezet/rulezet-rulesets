rule TTP_XOR_QUAD_CurrentVersionRun_4261 {
  strings:
    $key_4261 = { 11 0e [2] 35 00 [2] 1e 2c [2] 30 0e [2] 24 15 [2] 2b 0f [2] 35 12 [2] 37 13 [2] 2c 15 [2] 30 12 [2] 2c 3d }

  condition:
    any of them
}