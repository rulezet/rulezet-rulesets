rule TTP_XOR_QUAD_CurrentVersionRun_4661 {
  strings:
    $key_4661 = { 15 0e [2] 31 00 [2] 1a 2c [2] 34 0e [2] 20 15 [2] 2f 0f [2] 31 12 [2] 33 13 [2] 28 15 [2] 34 12 [2] 28 3d }

  condition:
    any of them
}