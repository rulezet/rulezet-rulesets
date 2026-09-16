rule TTP_XOR_QUAD_CurrentVersionRun_5c61 {
  strings:
    $key_5c61 = { 0f 0e [2] 2b 00 [2] 00 2c [2] 2e 0e [2] 3a 15 [2] 35 0f [2] 2b 12 [2] 29 13 [2] 32 15 [2] 2e 12 [2] 32 3d }

  condition:
    any of them
}