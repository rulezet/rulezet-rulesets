rule TTP_XOR_QUAD_CurrentVersionRun_7c61 {
  strings:
    $key_7c61 = { 2f 0e [2] 0b 00 [2] 20 2c [2] 0e 0e [2] 1a 15 [2] 15 0f [2] 0b 12 [2] 09 13 [2] 12 15 [2] 0e 12 [2] 12 3d }

  condition:
    any of them
}