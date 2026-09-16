rule TTP_XOR_QUAD_CurrentVersionRun_0c61 {
  strings:
    $key_0c61 = { 5f 0e [2] 7b 00 [2] 50 2c [2] 7e 0e [2] 6a 15 [2] 65 0f [2] 7b 12 [2] 79 13 [2] 62 15 [2] 7e 12 [2] 62 3d }

  condition:
    any of them
}