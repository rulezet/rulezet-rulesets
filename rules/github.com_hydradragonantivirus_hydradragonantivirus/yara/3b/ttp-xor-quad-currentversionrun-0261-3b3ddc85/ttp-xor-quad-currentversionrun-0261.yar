rule TTP_XOR_QUAD_CurrentVersionRun_0261 {
  strings:
    $key_0261 = { 51 0e [2] 75 00 [2] 5e 2c [2] 70 0e [2] 64 15 [2] 6b 0f [2] 75 12 [2] 77 13 [2] 6c 15 [2] 70 12 [2] 6c 3d }

  condition:
    any of them
}