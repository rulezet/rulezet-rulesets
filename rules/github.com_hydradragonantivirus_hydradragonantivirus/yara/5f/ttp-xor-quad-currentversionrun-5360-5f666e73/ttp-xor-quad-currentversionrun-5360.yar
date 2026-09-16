rule TTP_XOR_QUAD_CurrentVersionRun_5360 {
  strings:
    $key_5360 = { 00 0f [2] 24 01 [2] 0f 2d [2] 21 0f [2] 35 14 [2] 3a 0e [2] 24 13 [2] 26 12 [2] 3d 14 [2] 21 13 [2] 3d 3c }

  condition:
    any of them
}