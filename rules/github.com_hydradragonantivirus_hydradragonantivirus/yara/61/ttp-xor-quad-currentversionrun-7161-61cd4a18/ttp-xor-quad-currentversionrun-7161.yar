rule TTP_XOR_QUAD_CurrentVersionRun_7161 {
  strings:
    $key_7161 = { 22 0e [2] 06 00 [2] 2d 2c [2] 03 0e [2] 17 15 [2] 18 0f [2] 06 12 [2] 04 13 [2] 1f 15 [2] 03 12 [2] 1f 3d }

  condition:
    any of them
}