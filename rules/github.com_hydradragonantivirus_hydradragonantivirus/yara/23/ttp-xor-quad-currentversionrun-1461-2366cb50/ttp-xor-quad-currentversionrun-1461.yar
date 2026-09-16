rule TTP_XOR_QUAD_CurrentVersionRun_1461 {
  strings:
    $key_1461 = { 47 0e [2] 63 00 [2] 48 2c [2] 66 0e [2] 72 15 [2] 7d 0f [2] 63 12 [2] 61 13 [2] 7a 15 [2] 66 12 [2] 7a 3d }

  condition:
    any of them
}