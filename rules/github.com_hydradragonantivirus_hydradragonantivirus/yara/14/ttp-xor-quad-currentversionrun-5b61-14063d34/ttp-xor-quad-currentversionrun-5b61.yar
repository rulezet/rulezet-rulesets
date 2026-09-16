rule TTP_XOR_QUAD_CurrentVersionRun_5b61 {
  strings:
    $key_5b61 = { 08 0e [2] 2c 00 [2] 07 2c [2] 29 0e [2] 3d 15 [2] 32 0f [2] 2c 12 [2] 2e 13 [2] 35 15 [2] 29 12 [2] 35 3d }

  condition:
    any of them
}