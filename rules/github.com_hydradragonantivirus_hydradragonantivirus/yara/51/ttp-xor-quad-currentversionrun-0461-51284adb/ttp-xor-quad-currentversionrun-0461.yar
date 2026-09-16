rule TTP_XOR_QUAD_CurrentVersionRun_0461 {
  strings:
    $key_0461 = { 57 0e [2] 73 00 [2] 58 2c [2] 76 0e [2] 62 15 [2] 6d 0f [2] 73 12 [2] 71 13 [2] 6a 15 [2] 76 12 [2] 6a 3d }

  condition:
    any of them
}