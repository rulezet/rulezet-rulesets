rule TTP_XOR_QUAD_CurrentVersionRun_3161 {
  strings:
    $key_3161 = { 62 0e [2] 46 00 [2] 6d 2c [2] 43 0e [2] 57 15 [2] 58 0f [2] 46 12 [2] 44 13 [2] 5f 15 [2] 43 12 [2] 5f 3d }

  condition:
    any of them
}